/*
Copyright 2025 the Unikorn Authors.
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

package types

import (
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
)

func (f Flavor) GPUCount() int {
	if f.GPU != nil {
		return f.GPU.LogicalCount
	}

	return 0
}

// OrganizationIDStrings converts typed organization IDs to their canonical
// string form for comparison against the string organization IDs/tags stored
// on provider images.
func OrganizationIDStrings(organizationIDs []identityids.OrganizationID) []string {
	ids := make([]string, len(organizationIDs))
	for i := range organizationIDs {
		ids[i] = organizationIDs[i].String()
	}

	return ids
}
