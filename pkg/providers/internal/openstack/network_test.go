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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/subnets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
)

func TestUpdateSubnetSendsHostRoutes(t *testing.T) {
	t.Parallel()

	const subnetID = "subnet-id"

	tests := []struct {
		name   string
		routes []subnets.HostRoute
		want   string
	}{
		{
			name:   "NoRoutesClearsThem",
			routes: []subnets.HostRoute{},
			want:   `[]`,
		},
		{
			name: "RoutesReplaceThem",
			routes: []subnets.HostRoute{
				{DestinationCIDR: "192.168.53.0/24", NextHop: "10.0.2.18"},
			},
			want: `[{"destination":"192.168.53.0/24","nexthop":"10.0.2.18"}]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPut, r.Method)
				assert.Equal(t, "/subnets/"+subnetID, r.URL.Path)

				var body struct {
					Subnet map[string]json.RawMessage `json:"subnet"`
				}

				if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
					http.Error(w, "invalid request body", http.StatusBadRequest)

					return
				}

				routes, ok := body.Subnet["host_routes"]
				if assert.True(t, ok, "host_routes must be sent") {
					assert.JSONEq(t, test.want, string(routes))
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)

				fmt.Fprintf(w, `{"subnet":{"id":"%s"}}`, subnetID)
			}))
			t.Cleanup(srv.Close)

			client := openstack.NewTestNetworkClient(srv.URL + "/")

			_, err := client.UpdateSubnet(t.Context(), subnetID, []string{"8.8.8.8"}, test.routes)
			require.NoError(t, err)
		})
	}
}
