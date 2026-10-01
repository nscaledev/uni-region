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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
)

func TestGetFlavorsFiltersUnsupportedIDs(t *testing.T) {
	t.Parallel()

	const (
		selectedID = "11111111-1111-4111-a111-111111111111"
		otherID    = "22222222-2222-4222-a222-222222222222"
	)

	cases := []struct {
		name    string
		options *unikornv1.RegionOpenstackComputeSpec
		want    []string
	}{
		{
			name: "public UUID flavors",
			want: []string{selectedID, otherID},
		},
		{
			name: "configured selector",
			options: &unikornv1.RegionOpenstackComputeSpec{Flavors: &unikornv1.OpenstackFlavorsSpec{
				Selector: &unikornv1.FlavorSelector{IDs: []string{selectedID, "42"}},
			}},
			want: []string{selectedID},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/flavors/detail" {
					http.NotFound(w, r)

					return
				}

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"flavors":[
					{"id":"11111111-1111-4111-a111-111111111111","name":"selected","vcpus":1,"ram":1024,"disk":10,"os-flavor-access:is_public":true},
					{"id":"22222222-2222-4222-a222-222222222222","name":"other","vcpus":2,"ram":2048,"disk":20,"os-flavor-access:is_public":true},
					{"id":"42","name":"numeric","vcpus":4,"ram":4096,"disk":40,"os-flavor-access:is_public":true},
					{"id":"33333333-3333-4333-a333-333333333333","name":"private","vcpus":8,"ram":8192,"disk":80,"os-flavor-access:is_public":false}
				]}`))
			}))
			t.Cleanup(server.Close)

			client := openstack.NewTestComputeClientWithOptions(server.URL+"/", tc.options)

			flavors, err := client.GetFlavors(t.Context())
			require.NoError(t, err)

			got := make([]string, len(flavors))
			for i := range flavors {
				got[i] = flavors[i].ID
			}

			require.Equal(t, tc.want, got)
		})
	}
}
