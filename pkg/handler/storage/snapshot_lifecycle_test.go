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

package storage_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityauth "github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/storage"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func snapshotMutationContext(ctx context.Context, operations ...identityapi.AclOperation) context.Context {
	ctx = identityauth.NewContext(ctx, &identityauth.Info{Userinfo: &identityapi.Userinfo{Sub: "creator@example.com"}})
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "creator@example.com"})

	return rbac.NewContext(ctx, &identityapi.Acl{Organizations: &identityapi.AclOrganizationList{{
		Id: testOrgID,
		Projects: &identityapi.AclProjectList{{
			Id: testProjID,
			Endpoints: identityapi.AclEndpoints{
				{
					Name:       "region:filestorage:v2",
					Operations: identityapi.AclOperations{identityapi.Read},
				},
				{
					Name:       "region:filestoragesnapshots:v2",
					Operations: operations,
				},
			},
		}},
	}}})
}

func TestCreateSnapshotReturnsCompletePendingIntent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
	parent := snapshotParent()
	parent.UID = "parent-lifetime"
	parent.Labels[constants.RegionLabel] = "a1111111-1111-4111-a111-111111111111"
	c := snapshotReadClient(t, parent)
	c.Clock = clocktesting.NewFakeClock(now)
	ctx := snapshotMutationContext(t.Context(), identityapi.Create, identityapi.Read)
	request := &openapi.FileStorageSnapshotV2Create{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        "Before.Upgrade",
			Description: ptr.To("Before upgrading the model"),
			Tags: &coreapi.TagList{{
				Name:  "environment",
				Value: "production",
			}},
		},
		Spec: openapi.FileStorageSnapshotV2CreateSpec{
			ExpirationTime: ptr.To(now.Add(time.Hour)),
			ProtectedPath:  ptr.To("datasets/model"),
		},
	}
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	got, err := c.CreateSnapshot(ctx, parentID, request)
	require.NoError(t, err)
	require.Equal(t, "Before.Upgrade", got.Metadata.Name)
	require.Equal(t, testOrgID, got.Metadata.OrganizationId)
	require.Equal(t, testProjID, got.Metadata.ProjectId)
	require.Equal(t, ptr.To("creator@example.com"), got.Metadata.CreatedBy)
	require.Equal(t, request.Metadata.Description, got.Metadata.Description)
	require.Equal(t, request.Metadata.Tags, got.Metadata.Tags)
	require.Equal(t, coreapi.ResourceProvisioningStatusPending, got.Metadata.ProvisioningStatus)
	require.Equal(t, coreapi.ResourceHealthStatusUnknown, got.Metadata.HealthStatus)
	require.Equal(t, openapi.FileStorageSnapshotV2Spec{
		FileStorageId:  parentID,
		ExpirationTime: ptr.To(now.Add(time.Hour)),
		ProtectedPath:  request.Spec.ProtectedPath,
	}, got.Spec)
	require.Equal(t, openapi.FileStorageSnapshotV2Status{}, got.Status)

	read, err := c.GetSnapshot(ctx, parentID, idstest.MustParseFileStorageSnapshotID(got.Metadata.Id))
	require.NoError(t, err)

	read.Spec.ExpirationTime = ptr.To(read.Spec.ExpirationTime.UTC())
	require.Equal(t, got, read)

	stored := &regionv1.FileStorageSnapshot{}
	require.NoError(t, c.Client.Get(ctx, client.ObjectKey{
		Namespace: snapshotNamespace,
		Name:      got.Metadata.Id,
	}, stored))
	require.Equal(t, "Before.Upgrade", stored.Spec.Name)
	require.Equal(t, corev1.TagList{{
		Name:  "environment",
		Value: "production",
	}}, stored.Spec.Tags)
	require.Empty(t, stored.Finalizers, "the lifecycle controller installs its own finalizer")
	require.Equal(t, []metav1.OwnerReference{{
		APIVersion:         regionv1.SchemeGroupVersion.String(),
		Kind:               "FileStorage",
		Name:               parent.Name,
		UID:                parent.UID,
		BlockOwnerDeletion: ptr.To(true),
	}}, stored.OwnerReferences)
	require.Equal(t, parent.Namespace, stored.Namespace)
	require.Equal(t, parent.Name, stored.Labels[constants.FileStorageLabel])
	require.Equal(t, parent.Labels[constants.RegionLabel], stored.Labels[constants.RegionLabel])
	require.Equal(t, "2", stored.Labels[constants.ResourceAPIVersionLabel])
	require.Equal(t, testOrgID, stored.Labels[coreconstants.OrganizationPrincipalLabel])
	require.Equal(t, testProjID, stored.Labels[coreconstants.ProjectPrincipalLabel])
	require.Equal(t, "creator@example.com", stored.Annotations[coreconstants.CreatorPrincipalAnnotation])
}

func TestCreateSnapshotRejectsInvalidIntent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)

	for _, test := range []struct {
		name   string
		change func(*openapi.FileStorageSnapshotV2Create)
	}{
		{
			name: "past expiration",
			change: func(r *openapi.FileStorageSnapshotV2Create) {
				r.Spec.ExpirationTime = ptr.To(now.Add(-time.Second))
			},
		},
		{
			name: "equal expiration",
			change: func(r *openapi.FileStorageSnapshotV2Create) {
				r.Spec.ExpirationTime = ptr.To(now)
			},
		},
		{
			name:   "dot path",
			change: func(r *openapi.FileStorageSnapshotV2Create) { r.Spec.ProtectedPath = ptr.To(".") },
		},
		{
			name:   "dot-dot path",
			change: func(r *openapi.FileStorageSnapshotV2Create) { r.Spec.ProtectedPath = ptr.To("..") },
		},
		{
			name:   "dot component",
			change: func(r *openapi.FileStorageSnapshotV2Create) { r.Spec.ProtectedPath = ptr.To("datasets/./model") },
		},
		{
			name:   "traversal",
			change: func(r *openapi.FileStorageSnapshotV2Create) { r.Spec.ProtectedPath = ptr.To("datasets/../model") },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c := snapshotReadClient(t, snapshotParent())
			c.Clock = clocktesting.NewFakeClock(now)
			request := &openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: "backup"}}
			test.change(request)

			ctx := snapshotMutationContext(t.Context(), identityapi.Create, identityapi.Read)
			parentID := idstest.MustParseFileStorageID(snapshotParentID)
			got, err := c.CreateSnapshot(ctx, parentID, request)
			require.Nil(t, got)
			require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422, got %v", err)
			list, err := c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
			require.NoError(t, err)
			require.Empty(t, list)
		})
	}
}

func TestCreateSnapshotRejectsDeletingParent(t *testing.T) {
	t.Parallel()

	parent := snapshotParent()
	parent.DeletionTimestamp = ptr.To(metav1.NewTime(time.Now()))
	parent.Finalizers = []string{coreconstants.Finalizer}
	c := snapshotReadClient(t, parent)
	ctx := snapshotMutationContext(t.Context(), identityapi.Create, identityapi.Read)
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	got, err := c.CreateSnapshot(ctx, parentID, &openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: "backup"}})
	require.Nil(t, got)
	require.True(t, coreerrors.IsConflict(err), "expected 409, got %v", err)
	list, err := c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
	require.NoError(t, err)
	require.Empty(t, list)
}

func TestDeleteSnapshotBeforeControllerReconciliationReleasesSlot(t *testing.T) {
	t.Parallel()

	// No lifecycle controller runs in this harness. Deleting untouched intent
	// must not wait for a finalizer installed by the create handler.
	c := snapshotReadClient(t, snapshotParent())
	ctx := snapshotMutationContext(t.Context(), identityapi.Create, identityapi.Read, identityapi.Delete)
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	request := &openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: "backup"}}
	created, err := c.CreateSnapshot(ctx, parentID, request)
	require.NoError(t, err)

	childID := idstest.MustParseFileStorageSnapshotID(created.Metadata.Id)
	require.NoError(t, c.DeleteSnapshot(ctx, parentID, childID))
	_, err = c.GetSnapshot(ctx, parentID, childID)
	requireSnapshotNotFound(t, err)
	recreated, err := c.CreateSnapshot(ctx, parentID, request)
	require.NoError(t, err)
	require.Equal(t, created.Metadata.Id, recreated.Metadata.Id)
}

func TestDeleteSnapshotRecordsIntentUntilFinalizerCompletes(t *testing.T) {
	t.Parallel()

	snapshot := manualSnapshot(snapshotID, "backup")
	snapshot.Finalizers = []string{coreconstants.Finalizer}
	snapshot.Spec.Pause = true
	snapshot.Annotations = map[string]string{coreconstants.CreatorAnnotation: "original@example.com"}
	c := snapshotReadClient(t, snapshotParent(), snapshot)
	ctx := snapshotMutationContext(t.Context(), identityapi.Delete, identityapi.Read)
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	childID := idstest.MustParseFileStorageSnapshotID(snapshotID)
	require.NoError(t, c.DeleteSnapshot(ctx, parentID, childID))
	got, err := c.GetSnapshot(ctx, parentID, childID)
	require.NoError(t, err)
	require.NotNil(t, got.Metadata.DeletionTime)
	require.Equal(t, coreapi.ResourceProvisioningStatusDeprovisioning, got.Metadata.ProvisioningStatus)
	require.Equal(t, ptr.To("original@example.com"), got.Metadata.CreatedBy)

	key := client.ObjectKey{
		Namespace: snapshotNamespace,
		Name:      snapshotID,
	}
	terminating := &regionv1.FileStorageSnapshot{}
	require.NoError(t, c.Client.Get(ctx, key, terminating))
	require.Equal(t, snapshot.Spec, terminating.Spec)
	require.Equal(t, []string{coreconstants.Finalizer}, terminating.Finalizers)
	require.NoError(t, c.DeleteSnapshot(ctx, parentID, childID))

	afterRetry := &regionv1.FileStorageSnapshot{}
	require.NoError(t, c.Client.Get(ctx, key, afterRetry))
	require.Equal(t, terminating, afterRetry)

	// Simulate successful controller cleanup; only that path removes the finalizer.
	terminating.Finalizers = nil
	require.NoError(t, c.Client.Update(ctx, terminating))
	_, err = c.GetSnapshot(ctx, parentID, childID)
	requireSnapshotNotFound(t, err)
	requireSnapshotNotFound(t, c.DeleteSnapshot(ctx, parentID, childID))
}

func TestDeleteSnapshotAcceptsConcurrentStatusUpdate(t *testing.T) {
	t.Parallel()

	snapshot := manualSnapshot(snapshotID, "backup")
	snapshot.Finalizers = []string{coreconstants.Finalizer}
	kube := snapshotReadClientBuilder(t, snapshotParent(), snapshot).WithStatusSubresource(&regionv1.FileStorageSnapshot{}).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, resource client.Object, options ...client.DeleteOption) error {
			// A controller write can reach storage before Region's cache sees it.
			current := &regionv1.FileStorageSnapshot{}
			require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(resource), current))
			current.Status.AbsoluteProtectedPath = ptr.To("/view/datasets")
			require.NoError(t, c.Status().Update(ctx, current))

			return c.Delete(ctx, resource, options...)
		},
	}).Build()
	c := storage.New(common.ClientArgs{
		Client:    kube,
		Namespace: snapshotNamespace,
	})
	ctx := snapshotMutationContext(t.Context(), identityapi.Delete, identityapi.Read)
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	childID := idstest.MustParseFileStorageSnapshotID(snapshotID)
	require.NoError(t, c.DeleteSnapshot(ctx, parentID, childID))
	got, err := c.GetSnapshot(ctx, parentID, childID)
	require.NoError(t, err)
	require.NotNil(t, got.Metadata.DeletionTime)
	require.Equal(t, ptr.To("/view/datasets"), got.Status.AbsoluteProtectedPath)
}

func TestDeleteSnapshotExpirationOverridesEveryLifecycleState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
	for _, deadline := range []struct {
		name string
		time time.Time
	}{
		{
			name: "at deadline",
			time: now,
		},
		{
			name: "after deadline",
			time: now.Add(-time.Second),
		},
	} {
		for _, state := range []string{"pending", "paused", "provisioning", "errored", "provisioned", "deleting"} {
			t.Run(deadline.name+"/"+state, func(t *testing.T) {
				t.Parallel()

				snapshot := manualSnapshot(snapshotID, "backup")
				snapshot.Spec.ExpirationTime = ptr.To(metav1.NewTime(deadline.time))
				snapshot.Finalizers = []string{coreconstants.Finalizer}

				switch state {
				case "paused":
					snapshot.Spec.Pause = true
				case "provisioning":
					snapshot.Status.Conditions = []metav1.Condition{{
						Type:   "Available",
						Status: metav1.ConditionFalse,
						Reason: "Provisioning",
					}}
				case "errored":
					snapshot.Status.Conditions = []metav1.Condition{{
						Type:   "Available",
						Status: metav1.ConditionFalse,
						Reason: "Errored",
					}}
				case "provisioned":
					snapshot.Status.Conditions = []metav1.Condition{{
						Type:   "Available",
						Status: metav1.ConditionTrue,
						Reason: "Provisioned",
					}}
				case "deleting":
					snapshot.DeletionTimestamp = ptr.To(metav1.NewTime(now.Add(-time.Minute)))
				}

				key := client.ObjectKey{
					Namespace: snapshotNamespace,
					Name:      snapshotID,
				}
				kube := snapshotReadClientBuilder(t, snapshotParent(), snapshot).WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
						t.Fatal("expired customer deletion must perform no resource mutation")
						return nil
					},
				}).Build()
				c := storage.New(common.ClientArgs{
					Client:    kube,
					Namespace: snapshotNamespace,
				})
				c.Clock = clocktesting.NewFakeClock(now)
				before := &regionv1.FileStorageSnapshot{}
				require.NoError(t, kube.Get(t.Context(), key, before))
				err := c.DeleteSnapshot(snapshotMutationContext(t.Context(), identityapi.Delete), idstest.MustParseFileStorageID(snapshotParentID), idstest.MustParseFileStorageSnapshotID(snapshotID))
				requireSnapshotNotFound(t, err)

				after := &regionv1.FileStorageSnapshot{}
				require.NoError(t, kube.Get(t.Context(), key, after))
				require.Equal(t, before, after, "expiry must leave intent, finalizers, status, and metadata unchanged")
			})
		}
	}
}

func TestDeleteSnapshotRetryCrossingExpirationPreservesCleanup(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
	snapshot := manualSnapshot(snapshotID, "backup")
	snapshot.Spec.ExpirationTime = ptr.To(metav1.NewTime(now.Add(time.Second)))
	snapshot.Finalizers = []string{coreconstants.Finalizer}
	c := snapshotReadClient(t, snapshotParent(), snapshot)
	clock := clocktesting.NewFakeClock(now)
	c.Clock = clock
	ctx := snapshotMutationContext(t.Context(), identityapi.Delete)
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	childID := idstest.MustParseFileStorageSnapshotID(snapshotID)
	require.NoError(t, c.DeleteSnapshot(ctx, parentID, childID))
	require.NoError(t, c.DeleteSnapshot(ctx, parentID, childID))

	key := client.ObjectKey{
		Namespace: snapshotNamespace,
		Name:      snapshotID,
	}
	before := &regionv1.FileStorageSnapshot{}
	require.NoError(t, c.Client.Get(ctx, key, before))
	require.NotNil(t, before.DeletionTimestamp)
	clock.Step(time.Second)
	requireSnapshotNotFound(t, c.DeleteSnapshot(ctx, parentID, childID))

	after := &regionv1.FileStorageSnapshot{}
	require.NoError(t, c.Client.Get(ctx, key, after))
	require.Equal(t, before, after)
	// Customer visibility does not gate internal finalizer-protected cleanup.
	after.Finalizers = nil
	require.NoError(t, c.Client.Update(ctx, after))
	requireSnapshotNotFound(t, c.DeleteSnapshot(ctx, parentID, childID))
}

func TestFileStorageDeleteRequestsForegroundCascade(t *testing.T) {
	t.Parallel()

	parent := snapshotParent()
	parent.Finalizers = []string{coreconstants.Finalizer}
	requests := 0
	kube := snapshotReadClientBuilder(t, parent).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, resource client.Object, options ...client.DeleteOption) error {
			requests++
			deleteOptions := (&client.DeleteOptions{}).ApplyOptions(options)
			require.Equal(t, ptr.To(metav1.DeletePropagationForeground), deleteOptions.PropagationPolicy)

			return c.Delete(ctx, resource, options...)
		},
	}).Build()
	c := storage.New(common.ClientArgs{
		Client:    kube,
		Namespace: snapshotNamespace,
	})
	ctx := rbac.NewContext(t.Context(), &identityapi.Acl{Global: &identityapi.AclEndpoints{{
		Name:       "region:filestorage:v2",
		Operations: identityapi.AclOperations{identityapi.Read, identityapi.Delete},
	}}})
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	require.NoError(t, c.Delete(ctx, parentID))
	require.NoError(t, c.Delete(ctx, parentID))
	require.Equal(t, 1, requests)
	// Parent cleanup requires only File Storage grants, never a snapshot grant.
	got, err := c.Get(ctx, parentID)
	require.NoError(t, err)
	require.NotNil(t, got.Metadata.DeletionTime)
	require.Equal(t, coreapi.ResourceProvisioningStatusDeprovisioning, got.Metadata.ProvisioningStatus)
}

func TestCreateSnapshotIdentityGolden(t *testing.T) {
	t.Parallel()

	// Independent vectors for core's UUIDv5 generation, including its rehash
	// of digit-leading results. These guard identity stability across upgrades.
	for _, test := range []struct {
		parent string
		name   string
		want   string
	}{
		{
			parent: "a4444444-4444-4444-a444-444444444444",
			name:   "backup",
			want:   "c70567b5-9757-5de1-a81d-b85d39a20c52",
		},
		{
			parent: "a4444444-4444-4444-a444-444444444444",
			name:   "Backup",
			want:   "e5be4812-24c1-5cd9-9d62-dae8d718158c",
		},
		{
			parent: "ab111111-1111-4111-a111-111111111111",
			name:   "backup",
			want:   "b83c61dd-1fdf-5a22-8514-065f98086d5a",
		},
		{
			parent: "F47AC10B-58CC-4372-A567-0E02B2C3D479",
			name:   "Before.Upgrade",
			want:   "cbf0d246-544c-586b-a502-24f2bcec1209",
		},
	} {
		t.Run(test.parent+"/"+test.name, func(t *testing.T) {
			t.Parallel()

			parentID := idstest.MustParseFileStorageID(test.parent)
			parent := snapshotParent()
			parent.Name = parentID.String()
			c := snapshotReadClient(t, parent)
			got, err := c.CreateSnapshot(snapshotMutationContext(t.Context(), identityapi.Create), parentID,
				&openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: test.name}})
			require.NoError(t, err)
			require.Equal(t, test.want, got.Metadata.Id)
			require.Equal(t, test.name, got.Metadata.Name)
		})
	}
}

func TestCreateSnapshotIdentityAndConflict(t *testing.T) {
	t.Parallel()

	other := snapshotParent()
	other.Name = snapshotOtherFileStorageID
	c := snapshotReadClient(t, snapshotParent(), other)
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	create := &openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: "backup"}}
	first, err := c.CreateSnapshot(snapshotMutationContext(t.Context(), identityapi.Create), parentID, create)
	require.NoError(t, err)
	require.Equal(t, "c70567b5-9757-5de1-a81d-b85d39a20c52", first.Metadata.Id)
	require.Nil(t, first.Spec.ExpirationTime)
	require.Nil(t, first.Spec.ProtectedPath)
	duplicate, err := c.CreateSnapshot(snapshotMutationContext(t.Context(), identityapi.Create), parentID, create)
	require.Nil(t, duplicate)
	require.True(t, coreerrors.IsConflict(err))
	cased, err := c.CreateSnapshot(snapshotMutationContext(t.Context(), identityapi.Create), parentID, &openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: "Backup"}})
	require.NoError(t, err)
	require.Equal(t, "e5be4812-24c1-5cd9-9d62-dae8d718158c", cased.Metadata.Id)

	otherID := idstest.MustParseFileStorageID(other.Name)
	crossParent, err := c.CreateSnapshot(snapshotMutationContext(t.Context(), identityapi.Create), otherID, create)
	require.NoError(t, err)
	require.Equal(t, "b83c61dd-1fdf-5a22-8514-065f98086d5a", crossParent.Metadata.Id)
	requireSnapshotNotFound(t, c.DeleteSnapshot(snapshotMutationContext(t.Context(), identityapi.Delete), otherID, idstest.MustParseFileStorageSnapshotID(first.Metadata.Id)))

	childID := idstest.MustParseFileStorageSnapshotID(first.Metadata.Id)
	key := client.ObjectKey{
		Namespace: snapshotNamespace,
		Name:      first.Metadata.Id,
	}
	stored := &regionv1.FileStorageSnapshot{}
	require.NoError(t, c.Client.Get(t.Context(), key, stored))

	// Simulate the controller protecting intent before provisioning.
	stored.Finalizers = []string{coreconstants.Finalizer}
	require.NoError(t, c.Client.Update(t.Context(), stored))
	require.NoError(t, c.DeleteSnapshot(snapshotMutationContext(t.Context(), identityapi.Delete), parentID, childID))
	duplicate, err = c.CreateSnapshot(snapshotMutationContext(t.Context(), identityapi.Create), parentID, create)
	require.Nil(t, duplicate)
	require.True(t, coreerrors.IsConflict(err), "terminating children retain the natural-key slot")

	require.NoError(t, c.Client.Get(t.Context(), key, stored))

	stored.Finalizers = nil
	require.NoError(t, c.Client.Update(t.Context(), stored))
	recreated, err := c.CreateSnapshot(snapshotMutationContext(t.Context(), identityapi.Create), parentID, create)
	require.NoError(t, err)
	require.Equal(t, first.Metadata.Id, recreated.Metadata.Id)
}

func TestCreateSnapshotRejectsDeadlineWithinCurrentSecond(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 9, 12, 0, 0, 500000000, time.UTC)
	c := snapshotReadClient(t, snapshotParent())
	c.Clock = clocktesting.NewFakeClock(now)
	ctx := snapshotMutationContext(t.Context(), identityapi.Create, identityapi.Read)
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	created, err := c.CreateSnapshot(ctx, parentID, &openapi.FileStorageSnapshotV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "backup"},
		Spec: openapi.FileStorageSnapshotV2CreateSpec{
			ExpirationTime: ptr.To(now.Add(400 * time.Millisecond)),
		},
	})
	require.Nil(t, created)
	require.True(t, coreerrors.IsUnprocessableContent(err), "normalized deadline must be future: %v", err)
	list, err := c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
	require.NoError(t, err)
	require.Empty(t, list)
}

func TestCreateSnapshotNormalizesExpirationBeforeStorage(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 9, 12, 0, 0, 500000000, time.UTC)
	expiration := now.Add(1400 * time.Millisecond)
	want := time.Date(2026, time.October, 9, 12, 0, 1, 0, time.UTC)
	kube := snapshotReadClientBuilder(t, snapshotParent()).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, resource client.Object, options ...client.CreateOption) error {
			// The real API client serializes before persistence. Reproduce that
			// boundary to verify validation and serialization use the same deadline.
			data, err := json.Marshal(resource)
			require.NoError(t, err)
			decoded := &regionv1.FileStorageSnapshot{}
			require.NoError(t, json.Unmarshal(data, decoded))
			require.True(t, want.Equal(decoded.Spec.ExpirationTime.Time))

			return c.Create(ctx, decoded, options...)
		},
	}).Build()
	c := storage.New(common.ClientArgs{
		Client:    kube,
		Namespace: snapshotNamespace,
	})
	clock := clocktesting.NewFakeClock(now)
	c.Clock = clock
	ctx := snapshotMutationContext(t.Context(), identityapi.Create, identityapi.Read, identityapi.Delete)
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	created, err := c.CreateSnapshot(ctx, parentID, &openapi.FileStorageSnapshotV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "backup"},
		Spec:     openapi.FileStorageSnapshotV2CreateSpec{ExpirationTime: ptr.To(expiration)},
	})
	require.NoError(t, err)
	require.True(t, want.Equal(*created.Spec.ExpirationTime))

	childID := idstest.MustParseFileStorageSnapshotID(created.Metadata.Id)
	read, err := c.GetSnapshot(ctx, parentID, childID)
	require.NoError(t, err)
	require.True(t, want.Equal(*read.Spec.ExpirationTime))

	// Retain controller-protected deletion intent so the later 404 proves
	// expiration, rather than merely observing an already-removed resource.
	stored := &regionv1.FileStorageSnapshot{}
	require.NoError(t, kube.Get(ctx, client.ObjectKey{
		Namespace: snapshotNamespace,
		Name:      created.Metadata.Id,
	}, stored))

	stored.Finalizers = []string{coreconstants.Finalizer}
	require.NoError(t, kube.Update(ctx, stored))
	require.NoError(t, c.DeleteSnapshot(ctx, parentID, childID))
	clock.Step(500 * time.Millisecond)
	requireSnapshotNotFound(t, c.DeleteSnapshot(ctx, parentID, childID))
}

func TestSnapshotMutationRBACMatrix(t *testing.T) {
	t.Parallel()

	for _, scope := range []string{"global", "organization", "project"} {
		for _, operation := range []identityapi.AclOperation{identityapi.Create, identityapi.Read, identityapi.Update, identityapi.Delete, "none"} {
			t.Run(scope+"/"+string(operation), func(t *testing.T) {
				t.Parallel()

				endpoints := identityapi.AclEndpoints{
					{
						Name:       "region:filestorage:v2",
						Operations: identityapi.AclOperations{identityapi.Read},
					},
					{
						Name:       "region:filestoragesnapshots:v2",
						Operations: identityapi.AclOperations{operation},
					},
				}
				acl := &identityapi.Acl{}

				switch scope {
				case "global":
					acl.Global = &endpoints
				case "organization":
					acl.Organizations = &identityapi.AclOrganizationList{{
						Id:        testOrgID,
						Endpoints: &endpoints,
					}}
				case "project":
					acl.Organizations = &identityapi.AclOrganizationList{{
						Id: testOrgID,
						Projects: &identityapi.AclProjectList{{
							Id:        testProjID,
							Endpoints: endpoints,
						}},
					}}
				}

				snapshot := manualSnapshot(snapshotID, "backup")
				snapshot.Finalizers = []string{coreconstants.Finalizer}
				c := snapshotReadClient(t, snapshotParent(), snapshot)
				ctx := rbac.NewContext(snapshotMutationContext(t.Context()), acl)
				parentID := idstest.MustParseFileStorageID(snapshotParentID)
				got, err := c.CreateSnapshot(ctx, parentID, &openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: "new-backup"}})

				if operation == identityapi.Create {
					require.NoError(t, err, "Create must not require child Read/Delete or parent Create")
					require.Equal(t, "new-backup", got.Metadata.Name)
				} else {
					require.Nil(t, got)
					requireSnapshotNotFound(t, err)
				}

				err = c.DeleteSnapshot(ctx, parentID, idstest.MustParseFileStorageSnapshotID(snapshotID))

				if operation == identityapi.Delete {
					require.NoError(t, err, "Delete must not require child Read/Create or parent Delete")
				} else {
					requireSnapshotNotFound(t, err)
				}
			})
		}
	}
}
