/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

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

//nolint:revive,stylecheck
package handler

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/openapi/oidc"
	coreutil "github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/region/pkg/handler/region"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/server/util"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Kubernetes.
	client client.Client

	// options allows behaviour to be defined on the CLI.
	options *Options

	// authorizerOptions allows access to the identity service for RBAC callbacks.
	authorizerOptions *oidc.Options
}

func New(client client.Client, options *Options, authorizerOptions *oidc.Options) (*Handler, error) {
	h := &Handler{
		client:            client,
		options:           options,
		authorizerOptions: authorizerOptions,
	}

	return h, nil
}

func (h *Handler) setCacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d", h.options.CacheMaxAge/time.Second))
	w.Header().Add("Cache-Control", "private")
}

func (h *Handler) setUncacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-cache")
}

func (h *Handler) GetApiV1Regions(w http.ResponseWriter, r *http.Request) {
	result, err := region.NewClient(h.client).List(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1RegionsRegionIDFlavors(w http.ResponseWriter, r *http.Request, regionID openapi.RegionIDParameter) {
	provider, err := region.NewClient(h.client).Provider(r.Context(), regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := provider.Flavors(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// Apply ordering guarantees.
	sort.Stable(result)

	out := make(openapi.Flavors, 0, len(result))

	for _, r := range result {
		t := openapi.Flavor{
			Name:   r.Name,
			Cpus:   r.CPUs,
			Memory: int(r.Memory.Value()) >> 30,
			Disk:   int(r.Disk.Value()) / 1000000000,
		}

		if r.GPUs != 0 {
			t.Gpus = coreutil.ToPointer(r.GPUs)
		}

		out = append(out, t)
	}

	h.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, out)
}

func (h *Handler) GetApiV1RegionsRegionIDImages(w http.ResponseWriter, r *http.Request, regionID openapi.RegionIDParameter) {
	provider, err := region.NewClient(h.client).Provider(r.Context(), regionID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := provider.Images(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// Apply ordering guarantees.
	sort.Stable(result)

	out := make(openapi.Images, 0, len(result))

	for _, r := range result {
		out = append(out, openapi.Image{
			Name:     r.Name,
			Created:  r.Created,
			Modified: r.Modified,
			Versions: openapi.ImageVersions{
				Kubernetes: r.KubernetesVersion,
			},
		})
	}

	h.setCacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, out)
}
