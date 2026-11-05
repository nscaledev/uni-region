/*
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package storage

import (
	"context"
	"fmt"
	"slices"
	"strings"

	unikorncorev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	"github.com/unikorn-cloud/identity/pkg/authz"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// restoreTargetFileStorage is the only supported restore target type.
const restoreTargetFileStorage = "fileStorage"

// RestoreV2 creates a new File Storage from a Manual Snapshot. Scope, storage
// class and NFS settings come from the snapshot's File Storage, so a restore
// can never cross a project or region. The create saga does the rest, and adds
// a reference on the snapshot that the File Storage controller releases once
// the restore has finished.
func (c *Client) RestoreV2(ctx context.Context, storageID regionids.FileStorageID, snapshotID regionids.FileStorageSnapshotID, request *openapi.FileStorageSnapshotRestoreV2Create) (*openapi.FileStorageSnapshotRestoreV2Read, error) {
	if request.Target.Type != restoreTargetFileStorage {
		return nil, errors.HTTPUnprocessableContent("unsupported restore target type")
	}

	if request.Target.FileStorage == nil {
		return nil, errors.HTTPUnprocessableContent("target.fileStorage is required")
	}

	target := authz.Target{
		Endpoint:   endpoint,
		Operation:  authz.Create,
		Kind:       authz.Primary,
		ObjectName: request.Target.FileStorage.Metadata.Name,
	}

	authz.Declare(ctx, target)

	snapshot, parent, err := c.getRestoreSource(ctx, storageID, snapshotID)
	if err != nil {
		return nil, err
	}

	create, err := restoreCreateRequest(parent, request.Target.FileStorage)
	if err != nil {
		return nil, err
	}

	s, err := newCreateSaga(c, create)
	if err != nil {
		return nil, err
	}

	s.sourceSnapshot = snapshot

	if err := rbac.AllowProjectScopeCreateOn(ctx, c.Identity, target, s.organizationID, s.projectID); err != nil {
		return nil, err
	}

	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return &openapi.FileStorageSnapshotRestoreV2Read{
		Target: openapi.FileStorageSnapshotRestoreV2ReadTarget{
			Type:        restoreTargetFileStorage,
			FileStorage: convertV2(s.filestorage),
		},
	}, nil
}

// getRestoreSource reads the snapshot and its File Storage, and checks the
// caller may read the snapshot. Its state is validated by the create saga.
func (c *Client) getRestoreSource(ctx context.Context, storageID regionids.FileStorageID, snapshotID regionids.FileStorageSnapshotID) (*regionv1.FileStorageSnapshot, *regionv1.FileStorage, error) {
	snapshot := &regionv1.FileStorageSnapshot{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: snapshotID.String()}, snapshot); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, nil, fmt.Errorf("%w: unable to lookup snapshot", err)
	}

	if err := rbac.AllowProjectScopeReader(ctx, snapshotEndpoint, identityapi.Read, snapshot); err != nil {
		return nil, nil, snapshotAuthorizationError(err)
	}

	if !snapshotMatchesParentID(snapshot, storageID) || snapshotExpired(snapshot, c.Clock.Now()) {
		return nil, nil, errors.HTTPNotFound()
	}

	parent, err := c.getSnapshotParent(ctx, storageID)
	if err != nil {
		return nil, nil, err
	}

	return snapshot, parent, nil
}

// validateSourceSnapshot returns 409 unless the snapshot is live and has been captured.
func validateSourceSnapshot(snapshot *regionv1.FileStorageSnapshot) error {
	if snapshot.DeletionTimestamp != nil {
		return errors.HTTPConflict()
	}

	condition, err := unikorncorev1.GetAvailableCondition(snapshot)
	if err != nil || condition.Reason != unikorncorev1.ConditionReasonProvisioned {
		return errors.HTTPConflict()
	}

	return nil
}

// restoreCreateRequest maps a restore request onto a File Storage create request
// for the parent's scope, so the create saga can be reused as is.
func restoreCreateRequest(parent *regionv1.FileStorage, in *openapi.FileStorageSnapshotRestoreV2FileStorage) (*openapi.StorageV2Create, error) {
	regionID, err := regionids.ParseRegionID(parent.Labels[constants.RegionLabel])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid region ID", err)
	}

	organizationID, projectID, err := parent.OrganizationAndProjectID()
	if err != nil {
		return nil, err
	}

	parentSizeGiB := quantityToSizeGiB(parent.Spec.Size)

	sizeGiB := ptr.Deref(in.Spec.SizeGiB, parentSizeGiB)
	if sizeGiB < parentSizeGiB {
		return nil, errors.HTTPUnprocessableContent("size must be at least the size of the snapshot's file storage").
			WithValues("minimumSizeGiB", parentSizeGiB)
	}

	out := &openapi.StorageV2Create{
		Metadata: in.Metadata,
	}

	out.Spec.OrganizationId = organizationID.String()
	out.Spec.ProjectId = projectID.String()
	out.Spec.RegionId = regionID
	out.Spec.StorageClassId = parent.Spec.StorageClassID
	out.Spec.SizeGiB = sizeGiB
	out.Spec.StorageType = openapi.StorageTypeV2Spec{NFS: checkRegionNFS(parent.Spec.NFS)}
	out.Spec.Attachments = in.Spec.Attachments
	out.Spec.DefaultSnapshotProtectionEnabled = ptr.To(ptr.Deref(in.Spec.DefaultSnapshotProtectionEnabled, parent.Spec.DefaultSnapshotProtectionEnabled))

	return out, nil
}

// snapshotReference is the finalizer a File Storage holds on its source snapshot.
func (c *Client) snapshotReference(filestorage *regionv1.FileStorage) (string, error) {
	return manager.GenerateResourceReference(c.Client, filestorage)
}

// referenceSnapshot stops the source snapshot being deleted while the restore is
// in progress. The File Storage controller removes the reference when it is done.
func (s *createSaga) referenceSnapshot(ctx context.Context) error {
	return s.client.updateSnapshotReference(ctx, s.sourceSnapshot, s.filestorage, func(snapshot *regionv1.FileStorageSnapshot, reference string) error {
		if snapshot.DeletionTimestamp != nil {
			return errors.HTTPConflict()
		}

		controllerutil.AddFinalizer(snapshot, reference)

		return nil
	})
}

// unreferenceSnapshot is the compensation for referenceSnapshot.
func (s *createSaga) unreferenceSnapshot(ctx context.Context) error {
	return s.client.updateSnapshotReference(ctx, s.sourceSnapshot, s.filestorage, func(snapshot *regionv1.FileStorageSnapshot, reference string) error {
		controllerutil.RemoveFinalizer(snapshot, reference)

		return nil
	})
}

// updateSnapshotReference reads the snapshot and applies mutate with an
// optimistic-lock patch, retrying a conflict once, as network references do.
func (c *Client) updateSnapshotReference(ctx context.Context, snapshot *regionv1.FileStorageSnapshot, filestorage *regionv1.FileStorage, mutate func(*regionv1.FileStorageSnapshot, string) error) error {
	reference, err := c.snapshotReference(filestorage)
	if err != nil {
		return fmt.Errorf("%w: unable to generate snapshot reference", err)
	}

	return c.RetryConflictOnce(func() error {
		current := &regionv1.FileStorageSnapshot{}

		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(snapshot), current); err != nil {
			if kerrors.IsNotFound(err) {
				return errors.HTTPNotFound().WithError(err)
			}

			return fmt.Errorf("%w: unable to lookup snapshot", err)
		}

		updated := current.DeepCopy()

		if err := mutate(updated, reference); err != nil {
			return err
		}

		patch := client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})

		if err := c.Client.Patch(ctx, updated, patch); err != nil {
			if kerrors.IsConflict(err) {
				return err
			}

			return fmt.Errorf("%w: unable to update snapshot reference", err)
		}

		return nil
	})
}

// snapshotInUse reports whether a File Storage restore is holding a reference
// on the snapshot. Other finalizers, e.g. the snapshot controller's own, do not count.
func snapshotInUse(snapshot *regionv1.FileStorageSnapshot) bool {
	prefix := "filestorages." + regionv1.GroupName + "/"

	return slices.ContainsFunc(manager.GetResourceReferences(snapshot), func(reference string) bool {
		return strings.HasPrefix(reference, prefix)
	})
}
