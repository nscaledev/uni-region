//go:build integration

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

package compute_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

// newOpenStackMock emulates the slice of the OpenStack API the region service
// touches when listing images (Keystone auth, service catalog, Glance version
// discovery and image list), so the verifier can exercise the real provider
// path without a live cloud. Its URL (with "/v3") is set via
// StateManager.SetOpenstackEndpoint.
func newOpenStackMock() *httptest.Server {
	// Captured by the handler so responses can reference the server's own URL.
	var server *httptest.Server

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")

		switch {
		case r.URL.Path == "/v3/auth/tokens":
			writeKeystoneToken(w, server.URL)
		case strings.HasSuffix(path, "/images"):
			writeGlanceImages(w)
		case strings.HasSuffix(path, "/image"): // Glance version discovery.
			writeVersions(w, "v2.15", server.URL+"/image/v2/")
		case strings.HasSuffix(path, "/network"): // Neutron version discovery.
			writeVersions(w, "v2.0", server.URL+"/network/v2.0/")
		default:
			http.NotFound(w, r)
		}
	})

	server = httptest.NewServer(handler)

	return server
}

func writeKeystoneToken(w http.ResponseWriter, base string) {
	w.Header().Set("X-Subject-Token", "mock-subject-token")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	// The provider builds service clients on auth, so every bootstrapped service
	// must resolve from the catalog even if the current contract only exercises
	// image listing.
	service := func(id, svcType, url string) map[string]any {
		return map[string]any{
			"id":   id,
			"type": svcType,
			"name": id,
			"endpoints": []map[string]any{
				{
					"id":        id + "-public",
					"interface": "public",
					"region":    "RegionOne",
					"region_id": "RegionOne",
					"url":       url,
				},
			},
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"token": map[string]any{
			"expires_at": "2099-01-01T00:00:00.000000Z",
			"catalog": []map[string]any{
				service("keystone", "identity", base+"/v3"),
				service("nova", "compute", base+"/compute/v2.1"),
				service("glance", "image", base+"/image"),
				service("neutron", "network", base+"/network"),
				service("cinder", "block-storage", base+"/block-storage/v3"),
			},
		},
	})
}

func writeVersions(w http.ResponseWriter, id, selfHref string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"versions": []map[string]any{
			{
				"id":     id,
				"status": "CURRENT",
				"links": []map[string]any{
					{"rel": "self", "href": selfHref},
				},
			},
		},
	})
}

func writeGlanceImages(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema": "/v2/schemas/images",
		"first":  "/image/v2/images",
		"images": []map[string]any{
			{
				"id":               "f7e8d9c0-1234-4567-89ab-cdef01234567",
				"name":             "Ubuntu 22.04",
				"status":           "active",
				"visibility":       "public",
				"protected":        false,
				"container_format": "bare",
				"disk_format":      "qcow2",
				"min_disk":         20,
				"min_ram":          2048,
				"virtual_size":     21474836480,
				"created_at":       "2026-01-01T00:00:00Z",
				"updated_at":       "2026-01-01T00:00:00Z",
				// Properties required by the image validation schema.
				"unikorn:os:kernel":      "linux",
				"unikorn:os:family":      "debian",
				"unikorn:os:distro":      "ubuntu",
				"unikorn:os:version":     "22.04",
				"unikorn:virtualization": "any",
			},
		},
	})
}
