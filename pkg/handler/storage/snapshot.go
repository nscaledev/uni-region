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
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identitycommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const snapshotEndpoint = "region:filestoragesnapshots:v2"

// CreateSnapshot records immutable Manual Snapshot intent. The lifecycle
// controller owns the lifecycle finalizer, provider mutations, and cleanup;
// the request writes only the CR.
func (c *Client) CreateSnapshot(ctx context.Context, storageID regionids.FileStorageID, request *openapi.FileStorageSnapshotV2Create) (*openapi.FileStorageSnapshotV2Read, error) {
	parent, err := c.getSnapshotParent(ctx, storageID, identityapi.Create)
	if err != nil {
		return nil, err
	}

	if parent.DeletionTimestamp != nil {
		return nil, errors.HTTPConflict()
	}

	if err := principal.EnrichUserPrincipalProjectScopeReader(ctx, parent); err != nil {
		return nil, fmt.Errorf("%w: unable to set snapshot principal scope", err)
	}

	expirationTime, err := validateSnapshotCreate(request, c.Clock.Now())
	if err != nil {
		return nil, err
	}

	organizationID, projectID, err := parent.OrganizationAndProjectID()
	if err != nil {
		return nil, err
	}

	resource := &regionv1.FileStorageSnapshot{
		ObjectMeta: conversion.NewDeterministicObjectMetadata(&request.Metadata, c.Namespace,
			uuid.UUID(storageID), request.Metadata.Name).
			WithLabel(constants.FileStorageLabel, parent.Name).
			WithLabel(constants.RegionLabel, parent.Labels[constants.RegionLabel]).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.FileStorageSnapshotSpec{
			Name:           request.Metadata.Name,
			FileStorageID:  storageID,
			ExpirationTime: expirationTime,
			ProtectedPath:  request.Spec.ProtectedPath,
			Tags:           conversion.GenerateTagList(request.Metadata.Tags),
		},
	}

	if err := controllerutil.SetOwnerReference(parent, resource, c.Client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, fmt.Errorf("%w: failed to set snapshot owner", err)
	}

	if err := identitycommon.SetIdentityMetadataProjectScope(ctx, &resource.ObjectMeta, organizationID, projectID); err != nil {
		return nil, fmt.Errorf("%w: failed to set snapshot identity metadata", err)
	}

	if err := c.Client.Create(ctx, resource); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return nil, errors.HTTPConflict().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to create snapshot", err)
	}

	// Unobserved Available/Healthy conditions project to core's pending/unknown
	// initial state. Kubernetes owns creation time and UID, not the request.
	return convertSnapshot(resource), nil
}

func validateSnapshotCreate(request *openapi.FileStorageSnapshotV2Create, now time.Time) (*metav1.Time, error) {
	if err := validateSnapshotPolicyProtectedPath(request.Spec.ProtectedPath); err != nil {
		return nil, err
	}

	if request.Spec.ExpirationTime == nil {
		return nil, nil //nolint:nilnil // Omission means no automatic expiration.
	}

	// Validate the same whole-second deadline that metav1.Time will serialize.
	expiration := request.Spec.ExpirationTime.Truncate(time.Second)
	if !expiration.After(now) {
		return nil, errors.HTTPUnprocessableContent("expirationTime must be strictly in the future")
	}

	return ptr.To(metav1.NewTime(expiration)), nil
}

// DeleteSnapshot records customer deletion intent without changing attribution,
// immutable capture intent, status, or any controller-installed finalizer.
func (c *Client) DeleteSnapshot(ctx context.Context, storageID regionids.FileStorageID, snapshotID regionids.FileStorageSnapshotID) error {
	now := c.Clock.Now()

	parent, err := c.getSnapshotParent(ctx, storageID, identityapi.Delete)
	if err != nil {
		return err
	}

	resource := &regionv1.FileStorageSnapshot{}
	if err := c.Client.Get(ctx, client.ObjectKey{
		Namespace: c.Namespace,
		Name:      snapshotID.String(),
	}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to lookup snapshot", err)
	}

	// Expiration hides even a paused, errored, or already-terminating CR. This
	// customer visibility rule does not affect controller/cascade cleanup.
	if !snapshotBelongsToParent(resource, parent, storageID) || snapshotExpired(resource, now) {
		return errors.HTTPNotFound()
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	if err := c.Client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to delete snapshot", err)
	}

	return nil
}

// ListSnapshots lists non-expired Manual Snapshots within an authorized File
// Storage. Region intent and one request-time observation determine visibility.
func (c *Client) ListSnapshots(ctx context.Context, storageID regionids.FileStorageID, params openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams) (openapi.FileStorageSnapshotsV2Read, error) {
	now := c.Clock.Now()

	parent, err := c.getSnapshotParent(ctx, storageID, identityapi.Read)
	if err != nil {
		return nil, err
	}

	selector := labels.SelectorFromSet(map[string]string{
		constants.FileStorageLabel:        parent.Name,
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
		coreconstants.OrganizationLabel:   parent.Labels[coreconstants.OrganizationLabel],
		coreconstants.ProjectLabel:        parent.Labels[coreconstants.ProjectLabel],
	})

	result := &regionv1.FileStorageSnapshotList{}
	if err := c.Client.List(ctx, result, &client.ListOptions{Namespace: c.Namespace, LabelSelector: selector}); err != nil {
		return nil, fmt.Errorf("%w: unable to list snapshots", err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(snapshot regionv1.FileStorageSnapshot) bool {
		return !snapshotBelongsToParent(&snapshot, parent, storageID) ||
			snapshotExpired(&snapshot, now) || !snapshot.Spec.Tags.ContainsAll(tagSelector)
	})
	slices.SortStableFunc(result.Items, func(a, b regionv1.FileStorageSnapshot) int {
		return cmp.Or(cmp.Compare(a.Spec.Name, b.Spec.Name), cmp.Compare(a.Name, b.Name))
	})

	out := make(openapi.FileStorageSnapshotsV2Read, len(result.Items))
	for i := range result.Items {
		out[i] = *convertSnapshot(&result.Items[i])
	}

	return out, nil
}

// GetSnapshot reads one Manual Snapshot from the Region ledger, under its
// authorized parent. It never discovers or adopts provider snapshots.
func (c *Client) GetSnapshot(ctx context.Context, storageID regionids.FileStorageID, snapshotID regionids.FileStorageSnapshotID) (*openapi.FileStorageSnapshotV2Read, error) {
	now := c.Clock.Now()

	parent, err := c.getSnapshotParent(ctx, storageID, identityapi.Read)
	if err != nil {
		return nil, err
	}

	result := &regionv1.FileStorageSnapshot{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: snapshotID.String()}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup snapshot", err)
	}

	if !snapshotBelongsToParent(result, parent, storageID) || snapshotExpired(result, now) {
		return nil, errors.HTTPNotFound()
	}

	return convertSnapshot(result), nil
}

func convertSnapshot(in *regionv1.FileStorageSnapshot) *openapi.FileStorageSnapshotV2Read {
	out := &openapi.FileStorageSnapshotV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.FileStorageSnapshotV2Spec{
			FileStorageId: in.Spec.FileStorageID,
			ProtectedPath: in.Spec.ProtectedPath,
		},
		Status: openapi.FileStorageSnapshotV2Status{
			AbsoluteProtectedPath: in.Status.AbsoluteProtectedPath,
		},
	}
	// Manual Snapshot Name is immutable intent; its metadata label is a mirror.
	out.Metadata.Name = in.Spec.Name

	if in.Spec.ExpirationTime != nil {
		out.Spec.ExpirationTime = &in.Spec.ExpirationTime.Time
	}

	if in.Status.SnapshotTime != nil {
		out.Status.SnapshotTime = &in.Status.SnapshotTime.Time
	}

	return out
}

// getSnapshotParent resolves parent Read and the independent child grant before any
// child lookup. All visibility failures use the same canonical not-found body.
func (c *Client) getSnapshotParent(ctx context.Context, storageID regionids.FileStorageID, operation identityapi.AclOperation) (*regionv1.FileStorage, error) {
	parent, err := c.GetRaw(ctx, storageID.String())
	if err != nil {
		if errors.IsHTTPNotFound(err) || errors.IsForbidden(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, err
	}

	if err := rbac.AllowProjectScopeReader(ctx, snapshotEndpoint, operation, parent); err != nil {
		return nil, errors.HTTPNotFound().WithError(err)
	}

	return parent, nil
}

func snapshotBelongsToParent(snapshot *regionv1.FileStorageSnapshot, parent *regionv1.FileStorage, storageID regionids.FileStorageID) bool {
	return snapshot.Spec.FileStorageID == storageID &&
		snapshot.Labels[constants.FileStorageLabel] == parent.Name &&
		snapshot.Labels[coreconstants.OrganizationLabel] == parent.Labels[coreconstants.OrganizationLabel] &&
		snapshot.Labels[coreconstants.ProjectLabel] == parent.Labels[coreconstants.ProjectLabel] &&
		snapshot.Labels[constants.ResourceAPIVersionLabel] == constants.MarshalAPIVersion(2)
}

func snapshotExpired(snapshot *regionv1.FileStorageSnapshot, now time.Time) bool {
	return snapshot.Spec.ExpirationTime != nil && !snapshot.Spec.ExpirationTime.After(now)
}
