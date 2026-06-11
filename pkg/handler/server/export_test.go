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

package server

import (
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

//nolint:gochecknoglobals
var ConvertInstanceLifecyclePhase = convertInstanceLifecyclePhase

//nolint:gochecknoglobals
var ConvertPublicIPAllocation = convertPublicIPAllocation

// GenerateAllowedAddressPairs exposes the unexported method for unit testing.
// The generator receiver is unused by the function, so a zero-value instance suffices.
//
//nolint:gochecknoglobals
var GenerateAllowedAddressPairs = func(in *openapi.ServerNetworkAllowedAddressPairList) []unikornv1.ServerNetworkAddressPair {
	return (&generator{}).generateAllowedAddressPairs(in)
}
