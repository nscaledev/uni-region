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

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
)

func TestComputeVolumeAttachmentOperations(t *testing.T) {
	t.Parallel()

	const (
		serverID = "server-id"
		volumeID = "volume-id"
		device   = "/dev/vdb"
	)

	var (
		createBody map[string]any
		requests   []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/servers/"+serverID+"/os-volume_attachments":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)

				return
			}

			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"volumeAttachment":{"device":%q,"volumeId":%q,"serverId":%q}}`, device, volumeID, serverID)

		case r.Method == http.MethodGet && r.URL.Path == "/servers/"+serverID+"/os-volume_attachments/"+volumeID:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"volumeAttachment":{"device":%q,"volumeId":%q,"serverId":%q}}`, device, volumeID, serverID)

		case r.Method == http.MethodDelete && r.URL.Path == "/servers/"+serverID+"/os-volume_attachments/"+volumeID:
			w.WriteHeader(http.StatusAccepted)

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client := openstack.NewTestComputeClient(srv.URL + "/")

	created, err := client.CreateVolumeAttachment(t.Context(), serverID, volumeID)
	require.NoError(t, err)
	require.Equal(t, device, created.Device)
	require.Equal(t, volumeID, created.VolumeID)
	require.Equal(t, serverID, created.ServerID)
	require.Equal(t, map[string]any{
		"volumeAttachment": map[string]any{
			"volumeId": volumeID,
		},
	}, createBody)

	found, err := client.GetVolumeAttachment(t.Context(), serverID, volumeID)
	require.NoError(t, err)
	require.Equal(t, created, found)

	require.NoError(t, client.DeleteVolumeAttachment(t.Context(), serverID, volumeID))
	require.Equal(t, []string{
		"POST /servers/server-id/os-volume_attachments",
		"GET /servers/server-id/os-volume_attachments/volume-id",
		"DELETE /servers/server-id/os-volume_attachments/volume-id",
	}, requests)
}
