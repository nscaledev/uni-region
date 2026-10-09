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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/storage"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	snapshotNamespace           = "snapshot-read-test"
	snapshotParentID            = "a4444444-4444-4444-a444-444444444444"
	snapshotID                  = "a5555555-5555-4555-a555-555555555555"
	snapshotOtherFileStorageID  = "ab111111-1111-4111-a111-111111111111"
	snapshotOtherProjectID      = "ab222222-2222-4222-a222-222222222222"
	snapshotOtherOrganizationID = "ab333333-3333-4333-a333-333333333333"
)

func unavailableSnapshotReads() interceptor.Funcs {
	return interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
			if _, ok := object.(*regionv1.FileStorageSnapshot); ok {
				return errors.New("snapshot storage unavailable") //nolint:err113 // Test boundary failure.
			}

			return c.Get(ctx, key, object, options...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, options ...client.ListOption) error {
			if _, ok := list.(*regionv1.FileStorageSnapshotList); ok {
				return errors.New("snapshot storage unavailable") //nolint:err113 // Test boundary failure.
			}

			return c.List(ctx, list, options...)
		},
	}
}

func snapshotParent() *regionv1.FileStorage {
	return &regionv1.FileStorage{ObjectMeta: metav1.ObjectMeta{
		Name:      snapshotParentID,
		Namespace: snapshotNamespace,
		Labels: map[string]string{
			coreconstants.OrganizationLabel: testOrgID,
			coreconstants.ProjectLabel:      testProjID,
		},
	}}
}

func manualSnapshot(id, name string) *regionv1.FileStorageSnapshot {
	return &regionv1.FileStorageSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:              id,
			Namespace:         snapshotNamespace,
			CreationTimestamp: metav1.NewTime(time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)),
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   testOrgID,
				coreconstants.ProjectLabel:        testProjID,
				coreconstants.NameLabel:           name,
				constants.FileStorageLabel:        snapshotParentID,
				constants.ResourceAPIVersionLabel: "2",
			},
		},
		Spec: regionv1.FileStorageSnapshotSpec{
			Name:          name,
			FileStorageID: idstest.MustParseFileStorageID(snapshotParentID),
		},
	}
}

func snapshotReadContext(ctx context.Context) context.Context {
	return rbac.NewContext(ctx, &identityapi.Acl{
		Organizations: &identityapi.AclOrganizationList{{
			Id: testOrgID,
			Projects: &identityapi.AclProjectList{{
				Id: testProjID,
				Endpoints: identityapi.AclEndpoints{
					{Name: "region:filestorage:v2", Operations: identityapi.AclOperations{identityapi.Read}},
					{Name: "region:filestoragesnapshots:v2", Operations: identityapi.AclOperations{identityapi.Read}},
				},
			}},
		}},
	})
}

func snapshotReadClient(t *testing.T, objects ...client.Object) *storage.Client {
	t.Helper()

	return storage.New(common.ClientArgs{
		Client:    snapshotReadClientBuilder(t, objects...).Build(),
		Namespace: snapshotNamespace,
	})
}

func snapshotReadClientBuilder(t *testing.T, objects ...client.Object) *fake.ClientBuilder {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...)
}

func TestGetSnapshotProjectsCompleteReadModel(t *testing.T) {
	t.Parallel()

	snapshot := manualSnapshot(snapshotID, "Before.Upgrade")
	snapshot.Spec.Pause = true
	snapshot.Spec.ProtectedPath = ptr.To("datasets/model")
	snapshot.Spec.ExpirationTime = ptr.To(metav1.NewTime(time.Date(2036, time.September, 2, 10, 0, 0, 0, time.UTC)))
	snapshot.Spec.Tags = corev1.TagList{{Name: "environment", Value: "production"}}
	snapshot.Annotations = map[string]string{
		coreconstants.DescriptionAnnotation:       "Before upgrading the model",
		coreconstants.CreatorAnnotation:           "creator@example.com",
		coreconstants.ModifierAnnotation:          "editor@example.com",
		coreconstants.ModifiedTimestampAnnotation: "2026-09-01T10:05:00Z",
		"internal.example.com/provider-id":        "private-provider-id",
		"internal.example.com/error":              "raw provider diagnostic",
	}
	snapshot.Status.SnapshotTime = ptr.To(metav1.NewTime(time.Date(2026, time.September, 1, 10, 1, 0, 0, time.UTC)))
	snapshot.Status.AbsoluteProtectedPath = ptr.To("/exact//provider/path/")
	snapshot.Status.Conditions = []metav1.Condition{
		{Type: "Available", Status: metav1.ConditionTrue, Reason: "Provisioned", Message: "Snapshot captured"},
		{Type: "Healthy", Status: metav1.ConditionTrue, Reason: "Healthy", Message: "Capture readiness observed"},
	}
	c := snapshotReadClient(t, snapshotParent(), snapshot)

	got, err := c.GetSnapshot(snapshotReadContext(t.Context()), idstest.MustParseFileStorageID(snapshotParentID), idstest.MustParseFileStorageSnapshotID(snapshotID))
	require.NoError(t, err)
	require.NotNil(t, got.Spec.ExpirationTime)
	require.NotNil(t, got.Status.SnapshotTime)
	// Compare instants independently of Kubernetes timestamp location decoding.
	got.Metadata.CreationTime = got.Metadata.CreationTime.UTC()
	got.Spec.ExpirationTime = ptr.To(got.Spec.ExpirationTime.UTC())
	got.Status.SnapshotTime = ptr.To(got.Status.SnapshotTime.UTC())
	require.Equal(t, &openapi.FileStorageSnapshotV2Read{
		Metadata: coreapi.ProjectScopedResourceReadMetadata{
			Id:                       snapshotID,
			Name:                     "Before.Upgrade",
			OrganizationId:           testOrgID,
			ProjectId:                testProjID,
			CreationTime:             time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC),
			CreatedBy:                ptr.To("creator@example.com"),
			Description:              ptr.To("Before upgrading the model"),
			ModifiedBy:               ptr.To("editor@example.com"),
			ModifiedTime:             ptr.To(time.Date(2026, time.September, 1, 10, 5, 0, 0, time.UTC)),
			Tags:                     &coreapi.TagList{{Name: "environment", Value: "production"}},
			ProvisioningStatus:       coreapi.ResourceProvisioningStatusProvisioned,
			ProvisioningStatusDetail: &coreapi.ProvisioningStatusDetail{Reason: coreapi.ProvisioningStatusReasonProvisioned, Message: "Snapshot captured"},
			HealthStatus:             coreapi.ResourceHealthStatusHealthy,
			HealthStatusDetail:       &coreapi.HealthStatusDetail{Reason: coreapi.HealthStatusReasonHealthy, Message: "Capture readiness observed"},
		},
		Spec: openapi.FileStorageSnapshotV2Spec{
			FileStorageId:  idstest.MustParseFileStorageID(snapshotParentID),
			ExpirationTime: ptr.To(time.Date(2036, time.September, 2, 10, 0, 0, 0, time.UTC)),
			ProtectedPath:  ptr.To("datasets/model"),
		},
		Status: openapi.FileStorageSnapshotV2Status{
			SnapshotTime:          ptr.To(time.Date(2026, time.September, 1, 10, 1, 0, 0, time.UTC)),
			AbsoluteProtectedPath: ptr.To("/exact//provider/path/"),
		},
	}, got)

	data, err := json.Marshal(got)
	require.NoError(t, err)

	for _, private := range []string{"pause", "private-provider-id", "raw provider diagnostic", "conditions", "namespace"} {
		require.NotContains(t, string(data), private)
	}
}

func TestGetSnapshotExpiration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		expiration *metav1.Time
		expired    bool
	}{
		{name: "before now", expiration: ptr.To(metav1.NewTime(now.Add(-time.Second))), expired: true},
		{name: "equal to now", expiration: ptr.To(metav1.NewTime(now)), expired: true},
		{name: "after now", expiration: ptr.To(metav1.NewTime(now.Add(time.Second)))},
		{name: "omitted expiration"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			snapshot := manualSnapshot(snapshotID, "backup")
			snapshot.Spec.ExpirationTime = test.expiration
			c := snapshotReadClient(t, snapshotParent(), snapshot)
			c.Clock = clocktesting.NewFakeClock(now)

			got, err := c.GetSnapshot(snapshotReadContext(t.Context()), idstest.MustParseFileStorageID(snapshotParentID), idstest.MustParseFileStorageSnapshotID(snapshotID))
			if test.expired {
				require.Nil(t, got)
				require.True(t, coreerrors.IsHTTPNotFound(err))

				response := httptest.NewRecorder()
				coreerrors.HandleError(response, httptest.NewRequestWithContext(t.Context(), "GET", "/", nil), err)
				require.JSONEq(t, `{"error":"not_found","error_description":"resource not found","trace_id":"00000000000000000000000000000000"}`, response.Body.String())

				return
			}

			require.NoError(t, err)
			require.Equal(t, snapshotID, got.Metadata.Id)
			require.Equal(t, "backup", got.Metadata.Name)
			require.Equal(t, coreapi.ResourceProvisioningStatusPending, got.Metadata.ProvisioningStatus)
			require.Equal(t, coreapi.ResourceHealthStatusUnknown, got.Metadata.HealthStatus)
			require.Nil(t, got.Spec.ProtectedPath)
			require.Equal(t, openapi.FileStorageSnapshotV2Status{}, got.Status)
		})
	}
}

func TestListSnapshotsFiltersAndOrdersLedger(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	first := manualSnapshot("a6666666-6666-4666-a666-666666666666", "Backup")
	tied := manualSnapshot("a7777777-7777-4777-a777-777777777777", "Backup")
	last := manualSnapshot(snapshotID, "backup")
	last.Spec.ExpirationTime = ptr.To(metav1.NewTime(now.Add(time.Second)))
	last.DeletionTimestamp = ptr.To(metav1.NewTime(now.Add(-time.Minute)))
	last.Finalizers = []string{coreconstants.Finalizer}
	tied.Status.Conditions = []metav1.Condition{{Type: "Available", Status: metav1.ConditionFalse, Reason: "Errored", Message: "Snapshot creation request was rejected"}}

	for _, resource := range []*regionv1.FileStorageSnapshot{first, tied, last} {
		resource.Spec.Tags = corev1.TagList{{Name: "environment", Value: "production"}, {Name: "team", Value: "ml"}}
	}

	wrongParent := first.DeepCopy()
	wrongParent.Name = "a8888888-8888-4888-a888-888888888888"
	wrongParent.Spec.FileStorageID = idstest.MustParseFileStorageID(snapshotOtherFileStorageID)
	wrongProject := first.DeepCopy()
	wrongProject.Name = "a9999999-9999-4999-a999-999999999999"
	wrongProject.Labels[coreconstants.ProjectLabel] = snapshotOtherProjectID
	wrongTags := manualSnapshot("abbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb", "excluded")
	wrongTags.Spec.Tags = corev1.TagList{{Name: "environment", Value: "production"}}
	expired := first.DeepCopy()
	expired.Name = "accccccc-cccc-4ccc-accc-cccccccccccc"
	expired.Spec.ExpirationTime = ptr.To(metav1.NewTime(now))
	objects := []client.Object{snapshotParent(), last, tied, first, wrongParent, wrongProject, wrongTags, expired}
	c := snapshotReadClient(t, objects...)
	c.Clock = clocktesting.NewFakeClock(now)

	got, err := c.ListSnapshots(snapshotReadContext(t.Context()), idstest.MustParseFileStorageID(snapshotParentID), openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{
		Tag: ptr.To(coreapi.TagSelectorParameter{"environment=production", "team=ml"}),
	})
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, []string{first.Name, tied.Name, last.Name}, []string{got[0].Metadata.Id, got[1].Metadata.Id, got[2].Metadata.Id})
	require.Equal(t, []string{"Backup", "Backup", "backup"}, []string{got[0].Metadata.Name, got[1].Metadata.Name, got[2].Metadata.Name})
	require.Equal(t, coreapi.ResourceProvisioningStatusError, got[1].Metadata.ProvisioningStatus)
	require.Equal(t, "Snapshot creation request was rejected", got[1].Metadata.ProvisioningStatusDetail.Message)
	require.Equal(t, coreapi.ResourceProvisioningStatusDeprovisioning, got[2].Metadata.ProvisioningStatus)
	require.NotNil(t, got[2].Metadata.DeletionTime)

	for _, resource := range got {
		require.Equal(t, idstest.MustParseFileStorageID(snapshotParentID), resource.Spec.FileStorageId)
		require.Equal(t, testProjID, resource.Metadata.ProjectId)
		require.Equal(t, &coreapi.TagList{{Name: "environment", Value: "production"}, {Name: "team", Value: "ml"}}, resource.Metadata.Tags)
	}
}

func TestSnapshotReadsHideExpiredLifecycleStates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)

	for _, state := range []string{"pending", "deleting", "errored"} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()

			snapshot := manualSnapshot(snapshotID, "backup")
			snapshot.Spec.ExpirationTime = ptr.To(metav1.NewTime(now))

			switch state {
			case "deleting":
				snapshot.DeletionTimestamp = ptr.To(metav1.NewTime(now.Add(-time.Minute)))
				snapshot.Finalizers = []string{coreconstants.Finalizer}
			case "errored":
				snapshot.Status.Conditions = []metav1.Condition{{Type: "Available", Status: metav1.ConditionFalse, Reason: "Errored", Message: "Snapshot creation request was rejected"}}
			}

			c := snapshotReadClient(t, snapshotParent(), snapshot)
			c.Clock = clocktesting.NewFakeClock(now)
			ctx := snapshotReadContext(t.Context())
			parentID := idstest.MustParseFileStorageID(snapshotParentID)
			got, err := c.GetSnapshot(ctx, parentID, idstest.MustParseFileStorageSnapshotID(snapshotID))
			require.Nil(t, got)
			requireSnapshotNotFound(t, err)
			listed, err := c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
			require.NoError(t, err)
			require.Equal(t, openapi.FileStorageSnapshotsV2Read{}, listed)
		})
	}
}

func requireSnapshotNotFound(t *testing.T, err error) {
	t.Helper()

	require.True(t, coreerrors.IsHTTPNotFound(err), "expected canonical 404, got %v", err)

	response := httptest.NewRecorder()
	coreerrors.HandleError(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), err)
	require.Equal(t, http.StatusNotFound, response.Code)
	require.JSONEq(t, `{"error":"not_found","error_description":"resource not found","trace_id":"00000000000000000000000000000000"}`, response.Body.String())
}

func TestSnapshotReadsRequireBothParentProjectPermissions(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"none", "region:filestorage:v2", "region:filestoragesnapshots:v2"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()

			acl := &identityapi.Acl{Organizations: &identityapi.AclOrganizationList{{
				Id: testOrgID,
				Projects: &identityapi.AclProjectList{{
					Id:        testProjID,
					Endpoints: identityapi.AclEndpoints{{Name: endpoint, Operations: identityapi.AclOperations{identityapi.Read}}},
				}},
			}}}
			c := storage.New(common.ClientArgs{
				Client:    snapshotReadClientBuilder(t, snapshotParent(), manualSnapshot(snapshotID, "backup")).WithInterceptorFuncs(unavailableSnapshotReads()).Build(),
				Namespace: snapshotNamespace,
			})
			ctx := rbac.NewContext(t.Context(), acl)
			parentID := idstest.MustParseFileStorageID(snapshotParentID)
			_, err := c.GetSnapshot(ctx, parentID, idstest.MustParseFileStorageSnapshotID(snapshotID))
			requireSnapshotNotFound(t, err)
			_, err = c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
			requireSnapshotNotFound(t, err)
		})
	}
}

func TestSnapshotReadsPreserveStorageFailures(t *testing.T) {
	t.Parallel()

	c := storage.New(common.ClientArgs{
		Client:    snapshotReadClientBuilder(t, snapshotParent()).WithInterceptorFuncs(unavailableSnapshotReads()).Build(),
		Namespace: snapshotNamespace,
	})
	ctx := snapshotReadContext(t.Context())
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	_, err := c.GetSnapshot(ctx, parentID, idstest.MustParseFileStorageSnapshotID(snapshotID))
	require.Error(t, err)
	require.False(t, coreerrors.IsHTTPNotFound(err))
	_, err = c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
	require.Error(t, err)
	require.False(t, coreerrors.IsHTTPNotFound(err))
}

func TestGetSnapshotDoesNotDiscloseOtherParentsOrProjects(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		change func(*regionv1.FileStorageSnapshot)
	}{
		{name: "wrong parent intent", change: func(s *regionv1.FileStorageSnapshot) {
			s.Spec.FileStorageID = idstest.MustParseFileStorageID(snapshotOtherFileStorageID)
		}},
		{name: "wrong parent label", change: func(s *regionv1.FileStorageSnapshot) {
			s.Labels[constants.FileStorageLabel] = snapshotOtherFileStorageID
		}},
		{name: "other project", change: func(s *regionv1.FileStorageSnapshot) { s.Labels[coreconstants.ProjectLabel] = snapshotOtherProjectID }},
		{name: "other organization", change: func(s *regionv1.FileStorageSnapshot) {
			s.Labels[coreconstants.OrganizationLabel] = snapshotOtherOrganizationID
		}},
		{name: "missing scope", change: func(s *regionv1.FileStorageSnapshot) { delete(s.Labels, coreconstants.ProjectLabel) }},
		{name: "wrong API version", change: func(s *regionv1.FileStorageSnapshot) { s.Labels[constants.ResourceAPIVersionLabel] = "1" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			snapshot := manualSnapshot(snapshotID, "backup")
			test.change(snapshot)
			c := snapshotReadClient(t, snapshotParent(), snapshot)
			ctx := snapshotReadContext(t.Context())
			parentID := idstest.MustParseFileStorageID(snapshotParentID)
			_, err := c.GetSnapshot(ctx, parentID, idstest.MustParseFileStorageSnapshotID(snapshotID))
			requireSnapshotNotFound(t, err)
			listed, err := c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
			require.NoError(t, err)
			require.Empty(t, listed)
		})
	}
}

func TestSnapshotReadsMissingParentOrChild(t *testing.T) {
	t.Parallel()

	ctx := snapshotReadContext(t.Context())
	parentID := idstest.MustParseFileStorageID(snapshotParentID)
	snapshotID := idstest.MustParseFileStorageSnapshotID(snapshotID)
	c := snapshotReadClient(t, manualSnapshot(snapshotID.String(), "backup"))
	_, err := c.GetSnapshot(ctx, parentID, snapshotID)
	requireSnapshotNotFound(t, err)
	_, err = c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
	requireSnapshotNotFound(t, err)
	c = snapshotReadClient(t, snapshotParent())
	_, err = c.GetSnapshot(ctx, parentID, snapshotID)
	requireSnapshotNotFound(t, err)
	listed, err := c.ListSnapshots(ctx, parentID, openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
	require.NoError(t, err)
	require.Equal(t, openapi.FileStorageSnapshotsV2Read{}, listed)
}

func TestListSnapshotsExpirationBoundaries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	before := manualSnapshot("a1111111-1111-4111-a111-111111111111", "before")
	before.Spec.ExpirationTime = ptr.To(metav1.NewTime(now.Add(-time.Second)))
	equal := manualSnapshot("a2222222-2222-4222-a222-222222222222", "equal")
	equal.Spec.ExpirationTime = ptr.To(metav1.NewTime(now))
	after := manualSnapshot("a3333333-3333-4333-a333-333333333333", "after")
	after.Spec.ExpirationTime = ptr.To(metav1.NewTime(now.Add(time.Second)))
	omitted := manualSnapshot(snapshotID, "omitted")
	c := snapshotReadClient(t, snapshotParent(), before, equal, after, omitted)
	c.Clock = clocktesting.NewFakeClock(now)
	got, err := c.ListSnapshots(snapshotReadContext(t.Context()), idstest.MustParseFileStorageID(snapshotParentID), openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{})
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, "after", got[0].Metadata.Name)
	require.Equal(t, "omitted", got[1].Metadata.Name)
	require.True(t, now.Add(time.Second).Equal(*got[0].Spec.ExpirationTime))
	require.Nil(t, got[1].Spec.ExpirationTime)
}

func TestListSnapshotsRejectsMalformedTags(t *testing.T) {
	t.Parallel()

	c := snapshotReadClient(t, snapshotParent())
	_, err := c.ListSnapshots(snapshotReadContext(t.Context()), idstest.MustParseFileStorageID(snapshotParentID), openapi.GetApiV2FilestorageFilestorageIDSnapshotsParams{
		Tag: ptr.To(coreapi.TagSelectorParameter{"malformed"}),
	})
	require.True(t, coreerrors.IsBadRequest(err))
}
