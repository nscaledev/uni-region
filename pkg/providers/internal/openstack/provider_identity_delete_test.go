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

package openstack_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func identityInventory(body string) teardownRequest {
	return teardownRequest{http.MethodGet, "/servers/detail?limit=250", http.StatusOK, body}
}

func identityCleanup(status int) []teardownRequest {
	return []teardownRequest{
		{http.MethodDelete, "/os-keypairs/unikorn-openstack-provider", status, ""},
		{http.MethodDelete, "/os-server-groups/group-1", status, ""},
		{http.MethodDelete, "/v3/users/test-user-id", status, ""},
		{http.MethodDelete, "/v3/projects/test-project-id", status, ""},
	}
}

func identityForTeardown() *unikornv1.OpenstackIdentity {
	identity := contractOpenstackIdentity()
	identity.Spec.SSHKeyName = ptr.To("unikorn-openstack-provider")
	identity.Spec.ServerGroupID = ptr.To("group-1")

	return identity
}

func requireIdentityRetained(t *testing.T, cli client.Client) {
	t.Helper()

	identity := &unikornv1.OpenstackIdentity{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: contractNamespace, Name: contractIdentityID}, identity))
	require.Equal(t, identityForTeardown().Spec, identity.Spec)
}

func TestDeleteIdentityWaitsForProjectServers(t *testing.T) {
	t.Parallel()

	for name, server := range map[string]string{
		"active":                  `{"id":"nova-1","name":"unrelated-name","status":"ACTIVE"}`,
		"error without Region CR": `{"id":"nova-1","name":"lost-region-server","status":"ERROR"}`,
		"deleting":                `{"id":"nova-1","name":"unrelated-name","status":"ACTIVE","OS-EXT-STS:task_state":"deleting"}`,
		"unknown":                 `{"id":"nova-1","status":"UNKNOWN"}`,
		"minimal":                 `{"id":"nova-1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			endpoint := newTeardownOpenstack(t, identityInventory(`{"servers":[`+server+`]}`))
			cli := contractRetryClient(t, identityForTeardown())
			err := teardownProvider(cli, endpoint).DeleteIdentity(t.Context(), contractIdentity())
			require.ErrorIs(t, err, provisioners.ErrYield)
			require.Contains(t, err.Error(), "test-project-id")
			require.Contains(t, err.Error(), "1")
			requireIdentityRetained(t, cli)
		})
	}
}

func TestDeleteIdentityInventoryFailureRetainsCredentials(t *testing.T) {
	t.Parallel()

	for name, response := range map[string]teardownRequest{
		"unauthorized":                 {http.MethodGet, "/servers/detail?limit=250", 401, `{}`},
		"forbidden":                    {http.MethodGet, "/servers/detail?limit=250", 403, `{}`},
		"timeout":                      {http.MethodGet, "/servers/detail?limit=250", 504, `{}`},
		"malformed":                    identityInventory(`{"servers":`),
		"wrong type":                   identityInventory(`{"servers":"invalid"}`),
		"missing collection":           identityInventory(`{}`),
		"null collection":              identityInventory(`{"servers":null}`),
		"empty page with continuation": identityInventory(`{"servers":[],"servers_links":[{"rel":"next","href":"http://unused.invalid/next"}]}`),
		"empty continuation":           identityInventory(`{"servers":[],"servers_links":[{"rel":"next","href":""}]}`),
		"missing continuation":         identityInventory(`{"servers":[],"servers_links":[{"rel":"next"}]}`),
		"no content":                   {http.MethodGet, "/servers/detail?limit=250", 204, ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			steps := []teardownRequest{response}
			if response.status == 401 {
				steps = append(steps, response)
			}

			endpoint := newTeardownOpenstack(t, steps...)
			cli := contractRetryClient(t, identityForTeardown())
			err := teardownProvider(cli, endpoint).DeleteIdentity(t.Context(), contractIdentity())
			require.Error(t, err)
			require.NotErrorIs(t, err, provisioners.ErrYield)
			requireIdentityRetained(t, cli)
		})
	}
}

func TestDeleteIdentityPaginatedInventory(t *testing.T) {
	t.Parallel()

	for _, status := range []int{200, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()

			pages := 0

			var endpoint string

			ts := newContractFakeOpenstack(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/servers/detail" {
					if r.Method == http.MethodDelete {
						t.Errorf("inventory must block destructive request: %s %s", r.Method, r.URL.Path)
						http.Error(w, "unexpected delete", http.StatusInternalServerError)

						return true
					}

					return false
				}

				pages++

				if r.URL.Query().Get("name") != "" || r.URL.Query().Get("status") != "" || r.URL.Query().Get("limit") != "250" {
					t.Errorf("inventory must use an unfiltered bounded project list: %s", r.URL)
				}

				w.Header().Set("Content-Type", "application/json")

				if pages == 1 {
					fmt.Fprintf(w, `{"servers":[{"id":"a","name":"unrelated","status":"ERROR"}],"servers_links":[{"rel":"next","href":%q}]}`, endpoint+"/servers/detail?limit=250&marker=a")
				} else {
					w.WriteHeader(status)
					fmt.Fprint(w, `{"servers":[{"id":"b","status":"UNKNOWN"}]}`)
				}

				return true
			})
			endpoint = ts.URL
			cli := contractRetryClient(t, identityForTeardown())

			err := teardownProvider(cli, endpoint).DeleteIdentity(t.Context(), contractIdentity())
			if status == 200 {
				require.ErrorIs(t, err, provisioners.ErrYield)
				require.Contains(t, err.Error(), "2")
			} else {
				require.Error(t, err)
				require.NotErrorIs(t, err, provisioners.ErrYield)
			}

			require.Equal(t, 2, pages)
			requireIdentityRetained(t, cli)
		})
	}
}

func TestDeleteIdentityAfterInventoryEmpty(t *testing.T) {
	t.Parallel()

	for _, status := range []int{204, 404} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()

			steps := []teardownRequest{
				identityInventory(`{"servers":[{"id":"nova-1","name":"orphan","status":"ERROR"}]}`),
				identityInventory(`{"servers":[]}`),
				{http.MethodDelete, "/os-keypairs/unikorn-openstack-provider", 409, ""},
				identityInventory(`{"servers":[]}`),
			}
			steps = append(steps, identityCleanup(status)...)
			endpoint := newTeardownOpenstack(t, steps...)
			cli := contractRetryClient(t, identityForTeardown())
			region := contractRegion(endpoint)
			region.Spec.Openstack.ServiceAccountSecret = &unikornv1.NamespacedObject{Namespace: contractNamespace, Name: "manager"}
			require.NoError(t, cli.Create(t.Context(), region))
			require.NoError(t, cli.Create(t.Context(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: contractNamespace, Name: "manager"},
				Data: map[string][]byte{
					"domain-id": []byte("manager-domain"), "user-id": []byte("manager-user"),
					"password": []byte("manager-password"), "project-id": []byte("manager-project"),
				},
			}))
			require.ErrorIs(t, teardownProvider(cli, endpoint).DeleteIdentity(t.Context(), contractIdentity()), provisioners.ErrYield)
			requireIdentityRetained(t, cli)
			require.Error(t, teardownProvider(cli, endpoint).DeleteIdentity(t.Context(), contractIdentity()))
			requireIdentityRetained(t, cli)
			require.NoError(t, teardownProvider(cli, endpoint).DeleteIdentity(t.Context(), contractIdentity()))
			err := cli.Get(t.Context(), client.ObjectKey{Namespace: contractNamespace, Name: contractIdentityID}, &unikornv1.OpenstackIdentity{})
			require.True(t, kerrors.IsNotFound(err))
			// A subsequent delete retains the never-realized identity no-op.
			require.NoError(t, teardownProvider(cli, endpoint).DeleteIdentity(t.Context(), contractIdentity()))
		})
	}
}

func TestDeleteIdentityNeverRealized(t *testing.T) {
	t.Parallel()

	identity := identityForTeardown()
	identity.Spec.UserID = nil
	cli := contractRetryClient(t, identity)
	// No OpenStack endpoint can be used before the tenant user exists.
	require.NoError(t, teardownProvider(cli, "http://unused.invalid").DeleteIdentity(t.Context(), contractIdentity()))
}

func TestDeleteIdentityInventoryRequestCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	ts := newContractFakeOpenstack(t, func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/servers/detail" {
			return false
		}

		cancel()
		<-r.Context().Done()

		return true
	})
	cli := contractRetryClient(t, identityForTeardown())
	err := teardownProvider(cli, ts.URL).DeleteIdentity(ctx, contractIdentity())
	require.ErrorIs(t, err, context.Canceled)
	requireIdentityRetained(t, cli)
}
