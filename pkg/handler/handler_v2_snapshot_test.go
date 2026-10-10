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

package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-logr/zapr"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	coreconfig "github.com/unikorn-cloud/core/pkg/testing/config"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	validator "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	authmock "github.com/unikorn-cloud/identity/pkg/middleware/openapi/mock"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/test/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	snapshotHTTPNamespace = "snapshot-http-test"
	snapshotHTTPParentID  = "a4444444-4444-4444-a444-444444444444"
	snapshotHTTPOrgID     = "11111111-1111-4111-a111-111111111111"
	snapshotHTTPProjectID = "22222222-2222-4222-a222-222222222222"
)

func snapshotHTTPClient(t *testing.T, acl *identityapi.Acl, objects ...client.Object) (*api.APIClient, client.Client, *observer.ObservedLogs) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, regionv1.AddToScheme(scheme))
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&regionv1.FileStorageSnapshot{}).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, object client.Object, options ...client.CreateOption) error {
			// Simulate only the API server's local lifetime metadata assignment.
			object.SetUID(types.UID(uuid.NewString()))
			object.SetCreationTimestamp(metav1.NewTime(time.Now().UTC().Truncate(time.Second)))

			return c.Create(ctx, object, options...)
		},
	}).Build()
	h := &handler.Handler{ClientArgs: common.ClientArgs{
		Client:    kube,
		Namespace: snapshotHTTPNamespace,
	}}
	schema, err := helpers.NewSchema(openapi.GetSwagger)
	require.NoError(t, err)

	options := &validator.Options{}
	flags := pflag.NewFlagSet("snapshot-http", pflag.ContinueOnError)
	options.AddFlags(flags)
	require.NoError(t, flags.Set("runtime-schema-validation-panic", "true"))
	authorizer := authmock.NewMockAuthorizer(gomock.NewController(t))
	authorizer.EXPECT().Authorize(gomock.Any()).Return(&authorization.Info{Userinfo: &identityapi.Userinfo{
		Sub:                       "creator@example.com",
		HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{Acctype: identityapi.User},
	}}, nil).AnyTimes()
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(acl, nil).AnyTimes()

	router := chi.NewRouter()
	observedCore, logs := observer.New(zap.InfoLevel)
	logger := zapr.NewLogger(zap.New(observedCore))

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(log.IntoContext(r.Context(), logger)))
		})
	})
	router.Use(routeresolver.New(schema).Middleware)
	// Keep the relevant middleware order aligned with pkg/server/server.go.
	// This focused harness does not replace deployed production-wiring tests.
	server := httptest.NewServer(openapi.HandlerWithOptions(h, openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares: []openapi.MiddlewareFunc{
			audit.New("region", "test").Middleware,
			validator.NewValidator(options, authorizer).Middleware,
		},
	}))
	t.Cleanup(server.Close)

	return api.NewAPIClientWithConfig(&api.TestConfig{
		BaseConfig: coreconfig.BaseConfig{
			BaseURL:        server.URL,
			AuthToken:      "test-token",
			RequestTimeout: 5 * time.Second,
		},
		RegionBaseURL: server.URL,
	}), kube, logs
}

func snapshotHTTPParent() *regionv1.FileStorage {
	return &regionv1.FileStorage{ObjectMeta: metav1.ObjectMeta{
		Name:      snapshotHTTPParentID,
		Namespace: snapshotHTTPNamespace,
		UID:       "parent-lifetime",
		Labels: map[string]string{
			coreconstants.OrganizationLabel: snapshotHTTPOrgID,
			coreconstants.ProjectLabel:      snapshotHTTPProjectID,
		},
	}}
}

func snapshotHTTPACL() *identityapi.Acl {
	return &identityapi.Acl{Global: &identityapi.AclEndpoints{
		{
			Name:       "region:filestorage:v2",
			Operations: identityapi.AclOperations{identityapi.Read},
		},
		{
			Name:       "region:filestoragesnapshots:v2",
			Operations: identityapi.AclOperations{identityapi.Create, identityapi.Read, identityapi.Delete},
		},
	}}
}

func TestSnapshotHTTPCreateReturnsAcceptedPendingResource(t *testing.T) {
	t.Parallel()

	c, _, logs := snapshotHTTPClient(t, snapshotHTTPACL(), snapshotHTTPParent())
	created, err := c.CreateFileStorageSnapshot(t.Context(), snapshotHTTPParentID, openapi.FileStorageSnapshotV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "backup"},
	})
	require.NoError(t, err)
	require.Equal(t, "c70567b5-9757-5de1-a81d-b85d39a20c52", created.Metadata.Id)
	require.Equal(t, "backup", created.Metadata.Name)
	require.Equal(t, snapshotHTTPOrgID, created.Metadata.OrganizationId)
	require.Equal(t, snapshotHTTPProjectID, created.Metadata.ProjectId)
	require.Equal(t, coreapi.ResourceProvisioningStatusPending, created.Metadata.ProvisioningStatus)
	require.Equal(t, coreapi.ResourceHealthStatusUnknown, created.Metadata.HealthStatus)
	require.Nil(t, created.Spec.ExpirationTime)
	require.Nil(t, created.Spec.ProtectedPath)
	require.Equal(t, openapi.FileStorageSnapshotV2Status{}, created.Status)
	require.False(t, created.Metadata.CreationTime.IsZero())
	require.Equal(t, ptr.To("creator@example.com"), created.Metadata.CreatedBy)
	require.Len(t, logs.FilterMessage("audit").All(), 1)
	require.Empty(t, logs.FilterMessage("response openapi schema validation failure").All(), "request and response contracts must validate")
}

func requireSnapshotHTTPNotFound(t *testing.T, body *coreapi.Error) {
	t.Helper()

	require.NotNil(t, body.TraceId)
	require.Equal(t, &coreapi.Error{
		Error:            coreapi.NotFound,
		ErrorDescription: "resource not found",
		TraceId:          body.TraceId,
	}, body)
}

func TestSnapshotHTTPDeleteAndRecreation(t *testing.T) {
	t.Parallel()

	c, kube, logs := snapshotHTTPClient(t, snapshotHTTPACL(), snapshotHTTPParent())
	request := openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: "backup"}}
	created, err := c.CreateFileStorageSnapshot(t.Context(), snapshotHTTPParentID, request)
	require.NoError(t, err)
	duplicate, err := c.CreateFileStorageSnapshotExpectError(t.Context(), snapshotHTTPParentID, request, http.StatusConflict)
	require.NoError(t, err)
	require.Equal(t, coreapi.Conflict, duplicate.Error)

	key := client.ObjectKey{
		Namespace: snapshotHTTPNamespace,
		Name:      created.Metadata.Id,
	}
	stored := &regionv1.FileStorageSnapshot{}
	require.NoError(t, kube.Get(t.Context(), key, stored))
	originalUID := stored.UID
	require.NotEmpty(t, originalUID)

	// Simulate controller reconciliation before testing protected deletion.
	stored.Finalizers = []string{coreconstants.Finalizer}
	require.NoError(t, kube.Update(t.Context(), stored))
	require.NoError(t, c.DeleteFileStorageSnapshot(t.Context(), snapshotHTTPParentID, created.Metadata.Id))
	require.NoError(t, c.DeleteFileStorageSnapshot(t.Context(), snapshotHTTPParentID, created.Metadata.Id))
	deleting, err := c.GetFileStorageSnapshot(t.Context(), snapshotHTTPParentID, created.Metadata.Id)
	require.NoError(t, err)
	require.NotNil(t, deleting.Metadata.DeletionTime)
	require.Equal(t, coreapi.ResourceProvisioningStatusDeprovisioning, deleting.Metadata.ProvisioningStatus)
	require.Equal(t, created.Metadata.CreatedBy, deleting.Metadata.CreatedBy)
	duplicate, err = c.CreateFileStorageSnapshotExpectError(t.Context(), snapshotHTTPParentID, request, http.StatusConflict)
	require.NoError(t, err)
	require.Equal(t, coreapi.Conflict, duplicate.Error)

	// Successful backend cleanup removes the lifecycle finalizer, permitting GC.
	require.NoError(t, kube.Get(t.Context(), key, stored))
	stored.Finalizers = nil
	require.NoError(t, kube.Update(t.Context(), stored))
	missing, err := c.DeleteFileStorageSnapshotExpectError(t.Context(), snapshotHTTPParentID, created.Metadata.Id, http.StatusNotFound)
	require.NoError(t, err)
	requireSnapshotHTTPNotFound(t, missing)
	missing, err = c.GetFileStorageSnapshotExpectError(t.Context(), snapshotHTTPParentID, created.Metadata.Id, http.StatusNotFound)
	require.NoError(t, err)
	requireSnapshotHTTPNotFound(t, missing)
	recreated, err := c.CreateFileStorageSnapshot(t.Context(), snapshotHTTPParentID, request)
	require.NoError(t, err)
	require.Equal(t, created.Metadata.Id, recreated.Metadata.Id)
	require.Equal(t, coreapi.ResourceProvisioningStatusPending, recreated.Metadata.ProvisioningStatus)
	require.NoError(t, kube.Get(t.Context(), key, stored))
	require.NotEqual(t, originalUID, stored.UID)

	data, err := json.Marshal(recreated)
	require.NoError(t, err)
	require.NotContains(t, string(data), string(stored.UID), "Kubernetes lifetime metadata stays local")
	// Create/Delete traverse the existing audit middleware; reads do not audit.
	entries := logs.FilterMessage("audit").All()
	require.Len(t, entries, 7)
	require.Empty(t, logs.FilterMessage("response openapi schema validation failure").All())
}

func TestSnapshotHTTPValidatesCreatePayload(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		body   string
		status int
	}{
		{
			name:   "empty name",
			body:   `{"metadata":{"name":""},"spec":{}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "dot name",
			body:   `{"metadata":{"name":"."},"spec":{}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "dot-dot name",
			body:   `{"metadata":{"name":".."},"spec":{}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "too long name",
			body:   `{"metadata":{"name":"` + strings.Repeat("a", 64) + `"},"spec":{}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "whitespace name",
			body:   `{"metadata":{"name":" backup"},"spec":{}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "invalid name",
			body:   `{"metadata":{"name":"back/up"},"spec":{}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "invalid expiration",
			body:   `{"metadata":{"name":"backup"},"spec":{"expirationTime":"not-rfc3339"}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "single-digit hour",
			body:   `{"metadata":{"name":"backup"},"spec":{"expirationTime":"2036-01-01T0:00:00Z"}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "comma fraction",
			body:   `{"metadata":{"name":"backup"},"spec":{"expirationTime":"2036-01-01T00:00:00,5Z"}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "non-future expiration",
			body:   `{"metadata":{"name":"backup"},"spec":{"expirationTime":"2000-01-01T00:00:00Z"}}`,
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "null expiration",
			body:   `{"metadata":{"name":"backup"},"spec":{"expirationTime":null}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "traversal",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":"datasets/../models"}}`,
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "dot component",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":"datasets/./models"}}`,
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "dot path",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":"."}}`,
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "dot-dot path",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":".."}}`,
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "empty path",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":""}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "absolute path",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":"/models"}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "double slash",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":"datasets//models"}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "trailing slash",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":"datasets/"}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "too long path",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":"` + strings.Repeat("a", 1025) + `"}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "null path",
			body:   `{"metadata":{"name":"backup"},"spec":{"protectedPath":null}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "caller placement",
			body:   `{"metadata":{"name":"backup"},"spec":{"fileStorageId":"a4444444-4444-4444-a444-444444444444"}}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "caller status",
			body:   `{"metadata":{"name":"backup"},"spec":{},"status":{"snapshotTime":"2036-01-01T00:00:00Z"}}`,
			status: http.StatusBadRequest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c, _, _ := snapshotHTTPClient(t, snapshotHTTPACL(), snapshotHTTPParent())
			body, err := c.CreateFileStorageSnapshotRawJSONExpectError(t.Context(), snapshotHTTPParentID, json.RawMessage(test.body), test.status)
			require.NoError(t, err)

			if test.status == http.StatusBadRequest {
				require.Equal(t, coreapi.InvalidRequest, body.Error)
			} else {
				require.Equal(t, coreapi.UnprocessableContent, body.Error)
			}

			require.NotEmpty(t, body.ErrorDescription)
			list, err := c.ListFileStorageSnapshots(t.Context(), snapshotHTTPParentID)
			require.NoError(t, err)
			require.Empty(t, list)
		})
	}
}

func TestSnapshotHTTPExpiredDeleteIsCanonicalAndReadOnly(t *testing.T) {
	t.Parallel()

	for _, deleting := range []bool{false, true} {
		t.Run("deleting="+strconv.FormatBool(deleting), func(t *testing.T) {
			t.Parallel()

			snapshot := &regionv1.FileStorageSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "c70567b5-9757-5de1-a81d-b85d39a20c52",
					Namespace:  snapshotHTTPNamespace,
					Finalizers: []string{coreconstants.Finalizer},
					Labels: map[string]string{
						coreconstants.OrganizationLabel:   snapshotHTTPOrgID,
						coreconstants.ProjectLabel:        snapshotHTTPProjectID,
						constants.FileStorageLabel:        snapshotHTTPParentID,
						constants.ResourceAPIVersionLabel: "2",
					},
				},
				Spec: regionv1.FileStorageSnapshotSpec{
					Name:           "backup",
					FileStorageID:  idstest.MustParseFileStorageID(snapshotHTTPParentID),
					ExpirationTime: ptr.To(metav1.NewTime(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC))),
				},
			}
			if deleting {
				snapshot.DeletionTimestamp = ptr.To(metav1.NewTime(time.Now().Add(-time.Minute)))
			}

			c, kube, _ := snapshotHTTPClient(t, snapshotHTTPACL(), snapshotHTTPParent(), snapshot)
			key := client.ObjectKeyFromObject(snapshot)
			before := &regionv1.FileStorageSnapshot{}
			require.NoError(t, kube.Get(t.Context(), key, before))
			body, err := c.DeleteFileStorageSnapshotExpectError(t.Context(), snapshotHTTPParentID, snapshot.Name, http.StatusNotFound)
			require.NoError(t, err)
			requireSnapshotHTTPNotFound(t, body)

			after := &regionv1.FileStorageSnapshot{}
			require.NoError(t, kube.Get(t.Context(), key, after))
			require.Equal(t, before, after)
		})
	}
}

func TestSnapshotHTTPWrongParentDeleteIsCanonicalAndReadOnly(t *testing.T) {
	t.Parallel()

	other := snapshotHTTPParent()
	other.Name = "ab111111-1111-4111-a111-111111111111"
	other.UID = "other-parent-lifetime"
	c, _, _ := snapshotHTTPClient(t, snapshotHTTPACL(), snapshotHTTPParent(), other)
	created, err := c.CreateFileStorageSnapshot(t.Context(), snapshotHTTPParentID, openapi.FileStorageSnapshotV2Create{
		Metadata: coreapi.ResourceWriteMetadata{Name: "backup"},
	})
	require.NoError(t, err)
	body, err := c.DeleteFileStorageSnapshotExpectError(t.Context(), other.Name, created.Metadata.Id, http.StatusNotFound)
	require.NoError(t, err)
	requireSnapshotHTTPNotFound(t, body)
	read, err := c.GetFileStorageSnapshot(t.Context(), snapshotHTTPParentID, created.Metadata.Id)
	require.NoError(t, err)

	read.Metadata.CreationTime = read.Metadata.CreationTime.UTC()
	require.Equal(t, created, read)
	require.Nil(t, read.Metadata.DeletionTime)
}

func TestSnapshotHTTPAcceptsNameAndPathBoundaries(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"A", "Before.Upgrade_v2-1", strings.Repeat("a", 63)} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, _, logs := snapshotHTTPClient(t, snapshotHTTPACL(), snapshotHTTPParent())
			request := openapi.FileStorageSnapshotV2Create{
				Metadata: coreapi.ResourceWriteMetadata{Name: name},
				Spec: openapi.FileStorageSnapshotV2CreateSpec{
					ProtectedPath: ptr.To(strings.Repeat("a", 1024)),
				},
			}
			created, err := c.CreateFileStorageSnapshot(t.Context(), snapshotHTTPParentID, request)
			require.NoError(t, err)
			require.Equal(t, name, created.Metadata.Name)
			require.Equal(t, request.Spec.ProtectedPath, created.Spec.ProtectedPath)
			require.Empty(t, logs.FilterMessage("response openapi schema validation failure").All())
		})
	}
}

func TestSnapshotHTTPIndependentMutationGrants(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		parentRead bool
		operations identityapi.AclOperations
		create     bool
		delete     bool
	}{
		{
			name:       "parent and create only",
			parentRead: true,
			operations: identityapi.AclOperations{identityapi.Create},
			create:     true,
		},
		{
			name:       "parent and delete only",
			parentRead: true,
			operations: identityapi.AclOperations{identityapi.Delete},
			delete:     true,
		},
		{
			name:       "parent and read only",
			parentRead: true,
			operations: identityapi.AclOperations{identityapi.Read},
		},
		{
			name:       "parent and update only",
			parentRead: true,
			operations: identityapi.AclOperations{identityapi.Update},
		},
		{
			name:       "no snapshot grants",
			parentRead: true,
		},
		{
			name:       "no parent read",
			operations: identityapi.AclOperations{identityapi.Create, identityapi.Read, identityapi.Delete},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			acl := &identityapi.Acl{Global: &identityapi.AclEndpoints{{
				Name:       "region:filestoragesnapshots:v2",
				Operations: test.operations,
			}}}
			if test.parentRead {
				*acl.Global = append(*acl.Global, identityapi.AclEndpoint{
					Name:       "region:filestorage:v2",
					Operations: identityapi.AclOperations{identityapi.Read},
				})
			}

			c, _, _ := snapshotHTTPClient(t, acl, snapshotHTTPParent())
			request := openapi.FileStorageSnapshotV2Create{Metadata: coreapi.ResourceWriteMetadata{Name: "backup"}}

			if test.create {
				created, err := c.CreateFileStorageSnapshot(t.Context(), snapshotHTTPParentID, request)
				require.NoError(t, err)
				require.Equal(t, "backup", created.Metadata.Name)
			} else {
				body, err := c.CreateFileStorageSnapshotExpectError(t.Context(), snapshotHTTPParentID, request, http.StatusNotFound)
				require.NoError(t, err)
				requireSnapshotHTTPNotFound(t, body)
			}
			// A missing child cannot distinguish denied Delete from permitted Delete;
			// use a real seeded child under this parent for the Delete half of the matrix.
			child := &regionv1.FileStorageSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "cbf0d246-544c-586b-a502-24f2bcec1209",
					Namespace:  snapshotHTTPNamespace,
					Finalizers: []string{coreconstants.Finalizer},
					Labels: map[string]string{
						coreconstants.OrganizationLabel:   snapshotHTTPOrgID,
						coreconstants.ProjectLabel:        snapshotHTTPProjectID,
						constants.FileStorageLabel:        snapshotHTTPParentID,
						constants.ResourceAPIVersionLabel: "2",
					},
				},
				Spec: regionv1.FileStorageSnapshotSpec{
					Name:          "other-backup",
					FileStorageID: idstest.MustParseFileStorageID(snapshotHTTPParentID),
				},
			}
			deleteClient, _, _ := snapshotHTTPClient(t, acl, snapshotHTTPParent(), child)

			if test.delete {
				require.NoError(t, deleteClient.DeleteFileStorageSnapshot(t.Context(), snapshotHTTPParentID, child.Name))
			} else {
				body, err := deleteClient.DeleteFileStorageSnapshotExpectError(t.Context(), snapshotHTTPParentID, child.Name, http.StatusNotFound)
				require.NoError(t, err)
				requireSnapshotHTTPNotFound(t, body)
			}
		})
	}
}
