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

//nolint:testpackage
package storage

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	corev1 "github.com/unikorn-cloud/core/pkg/openapi"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityauth "github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	identitymock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	restoreParentID   = "a4444444-4444-4444-a444-444444444444"
	restoreSnapshotID = "a5555555-5555-4555-a555-555555555555"
	restoreOtherID    = "a6666666-6666-4666-a666-666666666666"
)

type restoreFixture struct {
	client   *Client
	k8s      client.Client
	parent   *regionv1.FileStorage
	snapshot *regionv1.FileStorageSnapshot
}

// newRestoreFixture builds a Client over a ready parent File Storage (10GiB) with one
// provisioned manual snapshot. mutate may change the snapshot and parent before they are stored.
func newRestoreFixture(t *testing.T, mutate func(*regionv1.FileStorage, *regionv1.FileStorageSnapshot)) *restoreFixture {
	t.Helper()

	parent := &regionv1.FileStorage{
		ObjectMeta: metav1.ObjectMeta{
			Name:      restoreParentID,
			Namespace: testNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: testOrganizationID,
				coreconstants.ProjectLabel:      testProjectID,
				constants.RegionLabel:           testRegionID,
			},
		},
		Spec: regionv1.FileStorageSpec{
			StorageClassID:                   "sc-1",
			Size:                             *gibToQuantity(10),
			DefaultSnapshotProtectionEnabled: true,
			NFS:                              &regionv1.NFS{RootSquash: false, POSIXACL: ptr.To(true)},
		},
	}

	snapshot := &regionv1.FileStorageSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      restoreSnapshotID,
			Namespace: testNamespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: testOrganizationID,
				coreconstants.ProjectLabel:      testProjectID,
				constants.FileStorageLabel:      restoreParentID,
			},
		},
		Spec: regionv1.FileStorageSnapshotSpec{
			Name:          "backup",
			FileStorageID: idstest.MustParseFileStorageID(restoreParentID),
		},
		Status: regionv1.FileStorageSnapshotStatus{
			Conditions: []metav1.Condition{{
				Type:   string(v1alpha1.ConditionAvailable),
				Status: metav1.ConditionTrue,
				Reason: string(v1alpha1.ConditionReasonProvisioned),
			}},
		},
	}

	if mutate != nil {
		mutate(parent, snapshot)
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockIdentity := identitymock.NewMockClientWithResponsesInterface(ctrl)
	mockIdentity.EXPECT().
		PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsWithResponse(gomock.Any(), identityids.MustParseOrganizationID(testOrganizationID), identityids.MustParseProjectID(testProjectID), gomock.Any()).
		Return(&identityopenapi.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusCreated},
			JSON201:      &identityopenapi.AllocationResponse{Metadata: corev1.ProjectScopedResourceReadMetadata{Id: testAllocationID}},
		}, nil).
		AnyTimes()

	k8s := newFakeClient(t,
		&regionv1.Region{ObjectMeta: metav1.ObjectMeta{Name: testRegionID, Namespace: testNamespace}},
		&regionv1.FileStorageClass{ObjectMeta: metav1.ObjectMeta{
			Name:      "sc-1",
			Namespace: testNamespace,
			Labels:    map[string]string{constants.RegionLabel: testRegionID},
		}},
		parent,
		snapshot,
	)

	return &restoreFixture{
		client: &Client{
			ClientArgs: common.ClientArgs{Client: k8s, Identity: mockIdentity, Namespace: testNamespace},
			Clock:      clocktesting.NewFakeClock(time.Date(2026, time.September, 2, 0, 0, 0, 0, time.UTC)),
		},
		k8s:      k8s,
		parent:   parent,
		snapshot: snapshot,
	}
}

func restoreContext(t *testing.T) context.Context {
	t.Helper()

	ctx := identityauth.NewContext(t.Context(), &identityauth.Info{Userinfo: &identityopenapi.Userinfo{Sub: "user-1"}})
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "actor@example.com", OrganizationID: testOrganizationID, ProjectID: testProjectID})

	return rbac.NewContext(ctx, &identityopenapi.Acl{
		Global: &identityopenapi.AclEndpoints{
			{Name: "region:filestorage:v2", Operations: identityopenapi.AclOperations{identityopenapi.Create}},
			{Name: snapshotEndpoint, Operations: identityopenapi.AclOperations{identityopenapi.Read, identityopenapi.Delete}},
			{Name: "region:networks:v2", Operations: identityopenapi.AclOperations{identityopenapi.Read}},
		},
	})
}

func restoreRequest(configure func(*openapi.FileStorageSnapshotRestoreV2FileStorage)) *openapi.FileStorageSnapshotRestoreV2Create {
	target := &openapi.FileStorageSnapshotRestoreV2FileStorage{
		Metadata: corev1.ResourceWriteMetadata{Name: "restored"},
	}

	if configure != nil {
		configure(target)
	}

	return &openapi.FileStorageSnapshotRestoreV2Create{
		Target: openapi.FileStorageSnapshotRestoreV2Target{Type: "fileStorage", FileStorage: target},
	}
}

func (f *restoreFixture) restore(t *testing.T, request *openapi.FileStorageSnapshotRestoreV2Create) (*openapi.FileStorageSnapshotRestoreV2Read, error) {
	t.Helper()

	return f.client.RestoreV2(restoreContext(t), idstest.MustParseFileStorageID(restoreParentID), idstest.MustParseFileStorageSnapshotID(restoreSnapshotID), request)
}

// restoredFileStorage checks the response names its target and returns the File Storage.
func restoredFileStorage(t *testing.T, in *openapi.FileStorageSnapshotRestoreV2Read) *openapi.StorageV2Read {
	t.Helper()

	require.Equal(t, "fileStorage", in.Target.Type)
	require.NotNil(t, in.Target.FileStorage)

	return in.Target.FileStorage
}

func TestRestoreV2CreatesFileStorageFromSnapshot(t *testing.T) {
	t.Parallel()

	f := newRestoreFixture(t, nil)

	result, err := f.restore(t, restoreRequest(nil))
	require.NoError(t, err)

	got := restoredFileStorage(t, result)

	// Scope, class, NFS and protection come from the source; size defaults to the source size.
	require.Equal(t, "restored", got.Metadata.Name)
	require.Equal(t, int64(10), got.Spec.SizeGiB)
	require.Equal(t, "sc-1", got.Status.StorageClassId)
	require.Equal(t, testRegionID, got.Status.RegionId)
	require.False(t, got.Spec.StorageType.NFS.RootSquash)
	require.Equal(t, ptr.To(true), got.Spec.StorageType.NFS.PosixAcl)
	require.Equal(t, ptr.To(true), got.Spec.DefaultSnapshotProtectionEnabled)

	created := &regionv1.FileStorage{}
	require.NoError(t, f.k8s.Get(t.Context(), client.ObjectKey{Namespace: testNamespace, Name: got.Metadata.Id}, created))
	require.Equal(t, &regionv1.FileStorageSource{Snapshot: &regionv1.FileStorageSnapshotSource{ID: restoreSnapshotID}}, created.Spec.Source)

	// The snapshot is referenced by the new File Storage until the controller releases it.
	snapshot := &regionv1.FileStorageSnapshot{}
	require.NoError(t, f.k8s.Get(t.Context(), client.ObjectKeyFromObject(f.snapshot), snapshot))
	require.Contains(t, snapshot.Finalizers, "filestorages."+regionv1.GroupName+"/"+got.Metadata.Id)
}

func TestRestoreV2OverridesSizeAndDefaultProtection(t *testing.T) {
	t.Parallel()

	f := newRestoreFixture(t, nil)

	result, err := f.restore(t, restoreRequest(func(in *openapi.FileStorageSnapshotRestoreV2FileStorage) {
		in.Spec.SizeGiB = ptr.To(int64(20))
		in.Spec.DefaultSnapshotProtectionEnabled = ptr.To(false)
	}))
	require.NoError(t, err)

	got := restoredFileStorage(t, result)
	require.Equal(t, int64(20), got.Spec.SizeGiB)
	require.Equal(t, ptr.To(false), got.Spec.DefaultSnapshotProtectionEnabled)
}

func TestRestoreV2Rejections(t *testing.T) {
	t.Parallel()

	finalized := func(in *regionv1.FileStorageSnapshot) {
		in.Finalizers = []string{"test/finalizer"}
		in.DeletionTimestamp = ptr.To(metav1.Now())
	}

	tests := []struct {
		name    string
		mutate  func(*regionv1.FileStorage, *regionv1.FileStorageSnapshot)
		request func() *openapi.FileStorageSnapshotRestoreV2Create
		check   func(error) bool
	}{
		{
			name:   "snapshot not provisioned",
			mutate: func(_ *regionv1.FileStorage, s *regionv1.FileStorageSnapshot) { s.Status.Conditions = nil },
			check:  servererrors.IsConflict,
		},
		{
			name:   "snapshot deleting",
			mutate: func(_ *regionv1.FileStorage, s *regionv1.FileStorageSnapshot) { finalized(s) },
			check:  servererrors.IsConflict,
		},
		{
			name: "snapshot of another file storage",
			mutate: func(_ *regionv1.FileStorage, s *regionv1.FileStorageSnapshot) {
				s.Spec.FileStorageID = idstest.MustParseFileStorageID(restoreOtherID)
			},
			check: servererrors.IsHTTPNotFound,
		},
		{
			name: "expired snapshot",
			mutate: func(_ *regionv1.FileStorage, s *regionv1.FileStorageSnapshot) {
				s.Spec.ExpirationTime = ptr.To(metav1.NewTime(time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)))
			},
			check: servererrors.IsHTTPNotFound,
		},
		{
			name: "size below the source size",
			request: func() *openapi.FileStorageSnapshotRestoreV2Create {
				return restoreRequest(func(in *openapi.FileStorageSnapshotRestoreV2FileStorage) { in.Spec.SizeGiB = ptr.To(int64(9)) })
			},
			check: servererrors.IsUnprocessableContent,
		},
		{
			name: "unknown target type",
			request: func() *openapi.FileStorageSnapshotRestoreV2Create {
				request := restoreRequest(nil)
				request.Target.Type = "folder"

				return request
			},
			check: servererrors.IsUnprocessableContent,
		},
		{
			name: "missing file storage target",
			request: func() *openapi.FileStorageSnapshotRestoreV2Create {
				request := restoreRequest(nil)
				request.Target.FileStorage = nil

				return request
			},
			check: servererrors.IsUnprocessableContent,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			f := newRestoreFixture(t, test.mutate)

			request := restoreRequest(nil)
			if test.request != nil {
				request = test.request()
			}

			_, err := f.restore(t, request)
			require.Error(t, err)
			require.True(t, test.check(err), "unexpected error: %v", err)

			// A rejected restore must not leave a File Storage or a reference behind.
			list := &regionv1.FileStorageList{}
			require.NoError(t, f.k8s.List(t.Context(), list, client.InNamespace(testNamespace)))
			require.Len(t, list.Items, 1)

			snapshot := &regionv1.FileStorageSnapshot{}
			require.NoError(t, f.k8s.Get(t.Context(), client.ObjectKeyFromObject(f.snapshot), snapshot))
			require.False(t, snapshotInUse(snapshot))
		})
	}
}

func TestDeleteSnapshotBlockedWhileRestoring(t *testing.T) {
	t.Parallel()

	f := newRestoreFixture(t, func(_ *regionv1.FileStorage, s *regionv1.FileStorageSnapshot) {
		s.Finalizers = []string{"filestorages." + regionv1.GroupName + "/" + restoreOtherID}
	})

	err := f.client.DeleteSnapshot(restoreContext(t), idstest.MustParseFileStorageID(restoreParentID), idstest.MustParseFileStorageSnapshotID(restoreSnapshotID))
	require.Error(t, err)
	require.True(t, servererrors.IsConflict(err), "unexpected error: %v", err)

	snapshot := &regionv1.FileStorageSnapshot{}
	require.NoError(t, f.k8s.Get(t.Context(), client.ObjectKeyFromObject(f.snapshot), snapshot))
	require.Nil(t, snapshot.DeletionTimestamp)
}

func TestDeleteSnapshotIgnoresUnrelatedFinalizers(t *testing.T) {
	t.Parallel()

	f := newRestoreFixture(t, func(_ *regionv1.FileStorage, s *regionv1.FileStorageSnapshot) {
		s.Finalizers = []string{strings.Repeat("a", 3) + "/controller"}
	})

	require.NoError(t, f.client.DeleteSnapshot(restoreContext(t), idstest.MustParseFileStorageID(restoreParentID), idstest.MustParseFileStorageSnapshotID(restoreSnapshotID)))
}
