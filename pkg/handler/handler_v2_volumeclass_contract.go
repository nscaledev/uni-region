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

//nolint:revive
package handler

import (
	"errors"
	"net/http"

	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

var errVolumeClassListNotImplemented = errors.New("volume class list handler is not implemented")

// GetApiV2Volumeclasses keeps the generated server interface buildable while
// provider-backed VolumeClass discovery remains a separate implementation task.
func (*Handler) GetApiV2Volumeclasses(w http.ResponseWriter, r *http.Request, _ openapi.GetApiV2VolumeclassesParams) {
	servererrors.HandleError(w, r, errVolumeClassListNotImplemented)
}
