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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/util"
	identityauth "github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func directoryQuotaContext(ctx context.Context, sub string, operations ...identityapi.AclOperation) context.Context {
	ctx = identityauth.NewContext(ctx, &identityauth.Info{Userinfo: &identityapi.Userinfo{Sub: sub}})
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: sub})

	return rbac.NewContext(ctx, &identityapi.Acl{Organizations: &identityapi.AclOrganizationList{{
		Id: testOrgID,
		Projects: &identityapi.AclProjectList{{
			Id: testProjID,
			Endpoints: identityapi.AclEndpoints{
				{Name: "region:filestoragedirectoryquotas:v2", Operations: operations},
			},
		}},
	}}})
}

func allDirectoryQuotaOperations(ctx context.Context, sub string) context.Context {
	return directoryQuotaContext(ctx, sub, identityapi.Create, identityapi.Read, identityapi.Update, identityapi.Delete)
}

func directoryQuotaRequest(path string) *openapi.FileStorageDirectoryQuotaV2Create {
	update := directoryQuotaUpdateRequest()

	return &openapi.FileStorageDirectoryQuotaV2Create{
		Metadata: update.Metadata,
		Spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{
			Path:            path,
			DirectoryLimits: update.Spec.DirectoryLimits,
			Rules:           update.Spec.Rules,
		},
	}
}

func directoryQuotaUpdateRequest() *openapi.FileStorageDirectoryQuotaV2Update {
	return &openapi.FileStorageDirectoryQuotaV2Update{
		Metadata: coreapi.ResourceWriteMetadata{Name: "home"},
		Spec: openapi.FileStorageDirectoryQuotaV2UpdateSpec{
			DirectoryLimits: &openapi.FileStorageDirectoryQuotaLimits{CapacityBytes: ptr.To[int64](1 << 40), Inodes: ptr.To[int64](1000)},
			Rules: &openapi.FileStorageDirectoryQuotaRules{{
				Subject: openapi.FileStorageDirectoryQuotaSubject{Kind: openapi.FileStorageDirectoryQuotaSubjectKindUser, Name: ptr.To("alice")},
				Limits:  openapi.FileStorageDirectoryQuotaLimits{CapacityBytes: ptr.To[int64](1 << 30)},
			}},
		},
	}
}

func requireHTTPStatus(t *testing.T, err error, check func(error) bool) {
	t.Helper()
	require.Error(t, err)
	require.True(t, check(err), "unexpected error: %v", err)
}

func TestCreateDirectoryQuotaReturnsPendingResource(t *testing.T) {
	t.Parallel()

	parent := snapshotParent()
	parent.Labels[constants.RegionLabel] = "a1111111-1111-4111-a111-111111111111"
	c := snapshotReadClient(t, parent)
	ctx := allDirectoryQuotaOperations(t.Context(), "creator@example.com")
	parentID := idstest.MustParseFileStorageID(snapshotParentID)

	got, err := c.CreateDirectoryQuota(ctx, parentID, directoryQuotaRequest("home/alice"))
	require.NoError(t, err)
	require.Equal(t, "home", got.Metadata.Name)
	require.Equal(t, ptr.To("creator@example.com"), got.Metadata.CreatedBy)
	require.Equal(t, coreapi.ResourceProvisioningStatusPending, got.Metadata.ProvisioningStatus)
	require.Equal(t, parentID, got.Spec.FileStorageId)
	require.Equal(t, "home/alice", got.Spec.Path)
	require.Equal(t, ptr.To[int64](1<<40), got.Spec.DirectoryLimits.CapacityBytes)
	require.Equal(t, []openapi.FileStorageDirectoryQuotaRuleStatus{{
		Subject:            openapi.FileStorageDirectoryQuotaSubject{Kind: openapi.FileStorageDirectoryQuotaSubjectKindUser, Name: ptr.To("alice")},
		ProvisioningStatus: coreapi.ResourceProvisioningStatusPending,
	}}, *got.Status.Rules)

	stored := &regionv1.FileStorageDirectoryQuota{}
	require.NoError(t, c.Client.Get(ctx, client.ObjectKey{Namespace: snapshotNamespace, Name: got.Metadata.Id}, stored))
	require.Equal(t, "1Ti", stored.Spec.DirectoryLimits.Capacity.String())
	require.Equal(t, snapshotParentID, stored.Labels[constants.FileStorageLabel])
	require.Equal(t, parent.Labels[constants.RegionLabel], stored.Labels[constants.RegionLabel])
	require.Equal(t, []string{coreconstants.Finalizer}, stored.Finalizers)
	require.Len(t, stored.OwnerReferences, 1)
	require.True(t, *stored.OwnerReferences[0].BlockOwnerDeletion)

	read, err := c.GetDirectoryQuota(ctx, parentID, idstest.MustParseFileStorageDirectoryQuotaID(got.Metadata.Id))
	require.NoError(t, err)
	require.Equal(t, got.Spec, read.Spec)
}

// A snapshot ID is hashed from the parent ID and the snapshot name, so a quota
// on a path equal to a snapshot name must not get the same ID.
func TestCreateDirectoryQuotaIDDiffersFromSnapshotID(t *testing.T) {
	t.Parallel()

	c := snapshotReadClient(t, snapshotParent())
	ctx := allDirectoryQuotaOperations(t.Context(), "creator@example.com")

	got, err := c.CreateDirectoryQuota(ctx, idstest.MustParseFileStorageID(snapshotParentID), directoryQuotaRequest("home"))
	require.NoError(t, err)
	require.NotEqual(t, coreutil.GenerateDeterministicResourceID(uuid.MustParse(snapshotParentID), "home"), got.Metadata.Id)
	// Golden vector: the ID is public, so its derivation must not drift.
	require.Equal(t, "e1539e84-c31b-547f-87e9-82522d3d3352", got.Metadata.Id)
}

func TestCreateDirectoryQuotaConflicts(t *testing.T) {
	t.Parallel()

	ctx := allDirectoryQuotaOperations(t.Context(), "creator@example.com")
	parentID := idstest.MustParseFileStorageID(snapshotParentID)

	t.Run("path already used", func(t *testing.T) {
		t.Parallel()

		c := snapshotReadClient(t, snapshotParent())
		_, err := c.CreateDirectoryQuota(ctx, parentID, directoryQuotaRequest("home/alice"))
		require.NoError(t, err)

		_, err = c.CreateDirectoryQuota(ctx, parentID, directoryQuotaRequest("home/alice"))
		requireHTTPStatus(t, err, coreerrors.IsConflict)

		_, err = c.CreateDirectoryQuota(ctx, parentID, directoryQuotaRequest("home/bob"))
		require.NoError(t, err)
	})

	t.Run("parent deleting", func(t *testing.T) {
		t.Parallel()

		parent := snapshotParent()
		parent.DeletionTimestamp = ptr.To(metav1.Now())
		parent.Finalizers = []string{coreconstants.Finalizer}
		c := snapshotReadClient(t, parent)
		_, err := c.CreateDirectoryQuota(ctx, parentID, directoryQuotaRequest("home/alice"))
		requireHTTPStatus(t, err, coreerrors.IsConflict)
	})

	t.Run("parent missing", func(t *testing.T) {
		t.Parallel()

		c := snapshotReadClient(t)
		_, err := c.CreateDirectoryQuota(ctx, parentID, directoryQuotaRequest("home/alice"))
		requireHTTPStatus(t, err, coreerrors.IsHTTPNotFound)
	})
}

func TestCreateDirectoryQuotaValidation(t *testing.T) {
	t.Parallel()

	limits := func(capacity, inodes *int64) *openapi.FileStorageDirectoryQuotaLimits {
		return &openapi.FileStorageDirectoryQuotaLimits{CapacityBytes: capacity, Inodes: inodes}
	}
	rule := func(kind openapi.FileStorageDirectoryQuotaSubjectKind, name *string, id *int64, l *openapi.FileStorageDirectoryQuotaLimits) openapi.FileStorageDirectoryQuotaRule {
		return openapi.FileStorageDirectoryQuotaRule{Subject: openapi.FileStorageDirectoryQuotaSubject{Kind: kind, Name: name, Id: id}, Limits: *l}
	}
	user := openapi.FileStorageDirectoryQuotaSubjectKindUser
	group := openapi.FileStorageDirectoryQuotaSubjectKindGroup

	for _, test := range []struct {
		name  string
		spec  openapi.FileStorageDirectoryQuotaV2CreateSpec
		valid bool
	}{
		{name: "dot component", spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home/./alice", DirectoryLimits: limits(ptr.To[int64](1), nil)}},
		{name: "dot-dot component", spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "..", DirectoryLimits: limits(ptr.To[int64](1), nil)}},
		{name: "no limits", spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home"}},
		{name: "empty rules only", spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home", Rules: &openapi.FileStorageDirectoryQuotaRules{}}},
		{name: "repeated subject", spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home", Rules: &openapi.FileStorageDirectoryQuotaRules{
			rule(user, ptr.To("alice"), nil, limits(ptr.To[int64](1), nil)),
			rule(user, ptr.To("alice"), nil, limits(ptr.To[int64](2), nil)),
		}}},
		{name: "same name and id differ by kind", valid: true, spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home", Rules: &openapi.FileStorageDirectoryQuotaRules{
			rule(user, ptr.To("ml"), nil, limits(ptr.To[int64](1), nil)),
			rule(group, ptr.To("ml"), nil, limits(ptr.To[int64](1), nil)),
			rule(user, nil, ptr.To[int64](0), limits(ptr.To[int64](1), nil)),
		}}},
		{name: "rule capacity above directory", spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home", DirectoryLimits: limits(ptr.To[int64](10), nil), Rules: &openapi.FileStorageDirectoryQuotaRules{
			rule(user, ptr.To("alice"), nil, limits(ptr.To[int64](11), nil)),
		}}},
		{name: "default inodes above directory", spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home", DirectoryLimits: limits(nil, ptr.To[int64](10)), DefaultGroupLimits: limits(nil, ptr.To[int64](11))}},
		{name: "limits equal to directory", valid: true, spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home", DirectoryLimits: limits(ptr.To[int64](10), ptr.To[int64](10)), DefaultUserLimits: limits(ptr.To[int64](10), ptr.To[int64](10))}},
		{name: "unbounded dimension is not compared", valid: true, spec: openapi.FileStorageDirectoryQuotaV2CreateSpec{Path: "home", DirectoryLimits: limits(nil, ptr.To[int64](10)), DefaultUserLimits: limits(ptr.To[int64](1<<50), nil)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c := snapshotReadClient(t, snapshotParent())
			_, err := c.CreateDirectoryQuota(allDirectoryQuotaOperations(t.Context(), "creator@example.com"), idstest.MustParseFileStorageID(snapshotParentID), &openapi.FileStorageDirectoryQuotaV2Create{
				Metadata: coreapi.ResourceWriteMetadata{Name: "home"},
				Spec:     test.spec,
			})

			if test.valid {
				require.NoError(t, err)
				return
			}

			requireHTTPStatus(t, err, coreerrors.IsUnprocessableContent)
		})
	}
}

func storedDirectoryQuota(id, name, path string) *regionv1.FileStorageDirectoryQuota {
	return &regionv1.FileStorageDirectoryQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      id,
			Namespace: snapshotNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: testOrgID,
				coreconstants.ProjectLabel:      testProjID,
				coreconstants.NameLabel:         name,
				constants.FileStorageLabel:      snapshotParentID,
			},
			Annotations: map[string]string{
				coreconstants.CreatorAnnotation: "creator@example.com",
			},
		},
		Spec: regionv1.FileStorageDirectoryQuotaSpec{
			FileStorageID:   idstest.MustParseFileStorageID(snapshotParentID),
			Path:            path,
			DirectoryLimits: &regionv1.FileStorageDirectoryQuotaLimits{Capacity: resource.NewQuantity(1<<40, resource.BinarySI)},
		},
	}
}

func TestGetDirectoryQuotaMergesRuleStatusAndUsage(t *testing.T) {
	t.Parallel()

	updatedAt := time.Date(2026, time.November, 1, 10, 0, 0, 0, time.UTC)
	alice := regionv1.FileStorageDirectoryQuotaSubject{Kind: regionv1.FileStorageDirectoryQuotaSubjectKindUser, Name: ptr.To("alice")}
	bob := regionv1.FileStorageDirectoryQuotaSubject{Kind: regionv1.FileStorageDirectoryQuotaSubjectKindUser, ID: ptr.To[int64](1001)}
	team := regionv1.FileStorageDirectoryQuotaSubject{Kind: regionv1.FileStorageDirectoryQuotaSubjectKindGroup, Name: ptr.To("alice")}
	limits := regionv1.FileStorageDirectoryQuotaLimits{Inodes: ptr.To[int64](10)}

	quota := storedDirectoryQuota(snapshotID, "home", "home")
	quota.Spec.Rules = []regionv1.FileStorageDirectoryQuotaRule{{Subject: alice, Limits: limits}, {Subject: bob, Limits: limits}, {Subject: team, Limits: limits}}
	quota.Generation = 2
	quota.Status.ObservedGeneration = ptr.To[int64](2)
	quota.Status.Rules = []regionv1.FileStorageDirectoryQuotaRuleStatus{
		{Subject: bob, ProvisioningStatus: regionv1.FileStorageDirectoryQuotaRuleErrored, Message: "unknown user"},
		{Subject: alice, ProvisioningStatus: regionv1.FileStorageDirectoryQuotaRuleProvisioned},
	}
	quota.Status.Usage = &regionv1.FileStorageDirectoryQuotaUsage{
		Directory: &regionv1.FileStorageDirectoryQuotaUsedAmount{UsedCapacity: resource.NewQuantity(2048, resource.BinarySI), UsedInodes: ptr.To[int64](3)},
		Rules: []regionv1.FileStorageDirectoryQuotaRuleUsage{
			{Subject: alice, Usage: regionv1.FileStorageDirectoryQuotaUsedAmount{UsedCapacity: resource.NewQuantity(1024, resource.BinarySI)}},
		},
		Timestamp: ptr.To(metav1.NewTime(updatedAt)),
	}

	c := snapshotReadClient(t, quota)
	got, err := c.GetDirectoryQuota(directoryQuotaContext(t.Context(), "reader@example.com", identityapi.Read),
		idstest.MustParseFileStorageID(snapshotParentID), idstest.MustParseFileStorageDirectoryQuotaID(snapshotID))
	require.NoError(t, err)

	got.Status.Usage.UpdatedAt = ptr.To(got.Status.Usage.UpdatedAt.UTC())
	require.Equal(t, &openapi.FileStorageDirectoryQuotaDirectoryUsage{UsedBytes: ptr.To[int64](2048), UsedInodes: ptr.To[int64](3), UpdatedAt: &updatedAt}, got.Status.Usage)
	require.Equal(t, []openapi.FileStorageDirectoryQuotaRuleStatus{
		{
			Subject:            openapi.FileStorageDirectoryQuotaSubject{Kind: openapi.FileStorageDirectoryQuotaSubjectKindUser, Name: ptr.To("alice")},
			ProvisioningStatus: coreapi.ResourceProvisioningStatusProvisioned,
			Usage:              &openapi.FileStorageDirectoryQuotaUsage{UsedBytes: ptr.To[int64](1024)},
		},
		{
			Subject:            openapi.FileStorageDirectoryQuotaSubject{Kind: openapi.FileStorageDirectoryQuotaSubjectKindUser, Id: ptr.To[int64](1001)},
			ProvisioningStatus: coreapi.ResourceProvisioningStatusError,
			Message:            ptr.To("unknown user"),
		},
		{
			Subject:            openapi.FileStorageDirectoryQuotaSubject{Kind: openapi.FileStorageDirectoryQuotaSubjectKindGroup, Name: ptr.To("alice")},
			ProvisioningStatus: coreapi.ResourceProvisioningStatusPending,
		},
	}, *got.Status.Rules)
}

func TestGetDirectoryQuotaRuleStatus(t *testing.T) {
	t.Parallel()

	alice := regionv1.FileStorageDirectoryQuotaSubject{Kind: regionv1.FileStorageDirectoryQuotaSubjectKindUser, Name: ptr.To("alice")}

	tests := []struct {
		name               string
		observedGeneration int64
		stored             regionv1.FileStorageDirectoryQuotaRuleStatus
		want               openapi.FileStorageDirectoryQuotaRuleStatus
	}{
		{
			name:               "stale status stays pending",
			observedGeneration: 1,
			stored:             regionv1.FileStorageDirectoryQuotaRuleStatus{Subject: alice, ProvisioningStatus: regionv1.FileStorageDirectoryQuotaRuleProvisioned},
			want:               openapi.FileStorageDirectoryQuotaRuleStatus{ProvisioningStatus: coreapi.ResourceProvisioningStatusPending},
		},
		{
			name:               "error without message omits message",
			observedGeneration: 2,
			stored:             regionv1.FileStorageDirectoryQuotaRuleStatus{Subject: alice, ProvisioningStatus: regionv1.FileStorageDirectoryQuotaRuleErrored},
			want:               openapi.FileStorageDirectoryQuotaRuleStatus{ProvisioningStatus: coreapi.ResourceProvisioningStatusError},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			quota := storedDirectoryQuota(snapshotID, "home", "home")
			quota.Generation = 2
			quota.Spec.Rules = []regionv1.FileStorageDirectoryQuotaRule{{Subject: alice, Limits: regionv1.FileStorageDirectoryQuotaLimits{Inodes: ptr.To[int64](10)}}}
			quota.Status.ObservedGeneration = ptr.To(test.observedGeneration)
			quota.Status.Rules = []regionv1.FileStorageDirectoryQuotaRuleStatus{test.stored}

			c := snapshotReadClient(t, quota)
			got, err := c.GetDirectoryQuota(directoryQuotaContext(t.Context(), "reader@example.com", identityapi.Read),
				idstest.MustParseFileStorageID(snapshotParentID), idstest.MustParseFileStorageDirectoryQuotaID(snapshotID))
			require.NoError(t, err)

			test.want.Subject = openapi.FileStorageDirectoryQuotaSubject{Kind: openapi.FileStorageDirectoryQuotaSubjectKindUser, Name: ptr.To("alice")}
			require.Equal(t, []openapi.FileStorageDirectoryQuotaRuleStatus{test.want}, *got.Status.Rules)
		})
	}
}

func TestGetDirectoryQuotaHidesOtherParentsAndProjects(t *testing.T) {
	t.Parallel()

	quotaID := idstest.MustParseFileStorageDirectoryQuotaID(snapshotID)
	c := snapshotReadClient(t, storedDirectoryQuota(snapshotID, "home", "home"))

	_, err := c.GetDirectoryQuota(directoryQuotaContext(t.Context(), "reader@example.com", identityapi.Read), idstest.MustParseFileStorageID(snapshotOtherFileStorageID), quotaID)
	requireHTTPStatus(t, err, coreerrors.IsHTTPNotFound)

	_, err = c.GetDirectoryQuota(directoryQuotaContext(t.Context(), "reader@example.com"), idstest.MustParseFileStorageID(snapshotParentID), quotaID)
	requireHTTPStatus(t, err, coreerrors.IsHTTPNotFound)
}

func TestListDirectoryQuotasFiltersAndOrders(t *testing.T) {
	t.Parallel()

	first := storedDirectoryQuota("a6666666-6666-4666-a666-666666666666", "a", "x")
	tied := storedDirectoryQuota("a7777777-7777-4777-a777-777777777777", "a", "y")
	last := storedDirectoryQuota(snapshotID, "b", "z")
	otherParent := storedDirectoryQuota("a9999999-9999-4999-a999-999999999999", "a", "w")
	otherParent.Labels[constants.FileStorageLabel] = snapshotOtherFileStorageID
	otherParent.Spec.FileStorageID = idstest.MustParseFileStorageID(snapshotOtherFileStorageID)

	c := snapshotReadClient(t, snapshotParent(), last, tied, otherParent, first)
	got, err := c.ListDirectoryQuotas(directoryQuotaContext(t.Context(), "reader@example.com", identityapi.Read),
		idstest.MustParseFileStorageID(snapshotParentID), openapi.GetApiV2FilestorageFilestorageIDDirectoryquotasParams{})
	require.NoError(t, err)

	ids := make([]string, len(got))
	for i := range got {
		ids[i] = got[i].Metadata.Id
	}

	require.Equal(t, []string{first.Name, tied.Name, last.Name}, ids)
}

func TestUpdateDirectoryQuota(t *testing.T) {
	t.Parallel()

	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	quotaID := idstest.MustParseFileStorageDirectoryQuotaID(snapshotID)

	t.Run("replaces everything but the path", func(t *testing.T) {
		t.Parallel()

		quota := storedDirectoryQuota(snapshotID, "home", "home")
		quota.Spec.DefaultUserLimits = &regionv1.FileStorageDirectoryQuotaLimits{Inodes: ptr.To[int64](5)}
		c := snapshotReadClient(t, quota)
		ctx := allDirectoryQuotaOperations(t.Context(), "editor@example.com")

		request := directoryQuotaUpdateRequest()
		request.Metadata.Name = "renamed"
		got, err := c.UpdateDirectoryQuota(ctx, parentID, quotaID, request)
		require.NoError(t, err)
		require.Equal(t, "renamed", got.Metadata.Name)
		require.Equal(t, "home", got.Spec.Path)
		require.Equal(t, ptr.To("creator@example.com"), got.Metadata.CreatedBy)
		require.Equal(t, ptr.To("editor@example.com"), got.Metadata.ModifiedBy)
		require.Nil(t, got.Spec.DefaultUserLimits)
		require.Len(t, *got.Spec.Rules, 1)

		stored := &regionv1.FileStorageDirectoryQuota{}
		require.NoError(t, c.Client.Get(ctx, client.ObjectKey{Namespace: snapshotNamespace, Name: snapshotID}, stored))
		require.Equal(t, snapshotID, stored.Name)
		require.Equal(t, "home", stored.Spec.Path)
		require.Nil(t, stored.Spec.DefaultUserLimits)
		require.Len(t, stored.Spec.Rules, 1)
	})

	t.Run("no limits", func(t *testing.T) {
		t.Parallel()

		c := snapshotReadClient(t, storedDirectoryQuota(snapshotID, "home", "home"))
		request := directoryQuotaUpdateRequest()
		request.Spec = openapi.FileStorageDirectoryQuotaV2UpdateSpec{}
		_, err := c.UpdateDirectoryQuota(allDirectoryQuotaOperations(t.Context(), "editor@example.com"), parentID, quotaID, request)
		requireHTTPStatus(t, err, coreerrors.IsUnprocessableContent)
	})

	t.Run("deleting", func(t *testing.T) {
		t.Parallel()

		quota := storedDirectoryQuota(snapshotID, "home", "home")
		quota.DeletionTimestamp = ptr.To(metav1.Now())
		quota.Finalizers = []string{coreconstants.Finalizer}
		c := snapshotReadClient(t, quota)
		_, err := c.UpdateDirectoryQuota(allDirectoryQuotaOperations(t.Context(), "editor@example.com"), parentID, quotaID, directoryQuotaUpdateRequest())
		requireHTTPStatus(t, err, coreerrors.IsConflict)
	})

	t.Run("read only caller", func(t *testing.T) {
		t.Parallel()

		c := snapshotReadClient(t, storedDirectoryQuota(snapshotID, "home", "home"))
		_, err := c.UpdateDirectoryQuota(directoryQuotaContext(t.Context(), "reader@example.com", identityapi.Read), parentID, quotaID, directoryQuotaUpdateRequest())
		requireHTTPStatus(t, err, coreerrors.IsHTTPNotFound)
	})
}

func TestDeleteDirectoryQuota(t *testing.T) {
	t.Parallel()

	quota := storedDirectoryQuota(snapshotID, "home", "home")
	quota.Finalizers = []string{coreconstants.Finalizer}
	c := snapshotReadClient(t, quota)
	ctx := allDirectoryQuotaOperations(t.Context(), "editor@example.com")
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	quotaID := idstest.MustParseFileStorageDirectoryQuotaID(snapshotID)

	require.NoError(t, c.DeleteDirectoryQuota(ctx, parentID, quotaID))
	// Deleting an already deleting quota is accepted again.
	require.NoError(t, c.DeleteDirectoryQuota(ctx, parentID, quotaID))

	stored := &regionv1.FileStorageDirectoryQuota{}
	require.NoError(t, c.Client.Get(ctx, client.ObjectKey{Namespace: snapshotNamespace, Name: snapshotID}, stored))
	require.NotNil(t, stored.DeletionTimestamp)

	err := c.DeleteDirectoryQuota(ctx, idstest.MustParseFileStorageID(snapshotOtherFileStorageID), quotaID)
	requireHTTPStatus(t, err, coreerrors.IsHTTPNotFound)
}
