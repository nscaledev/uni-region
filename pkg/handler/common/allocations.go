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

package common

import (
	"context"

	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CreateAllocation creates an Identity allocation for a handler resource.
func (c ClientArgs) CreateAllocation(ctx context.Context, resource client.Object, allocations identityapi.ResourceAllocationList) error {
	return identityclient.NewAllocations(c.Client, c.Identity).Create(ctx, resource, allocations)
}

// UpdateAllocation updates an Identity allocation for a handler resource.
func (c ClientArgs) UpdateAllocation(ctx context.Context, resource client.Object, allocations identityapi.ResourceAllocationList) error {
	return identityclient.NewAllocations(c.Client, c.Identity).Update(ctx, resource, allocations)
}

// DeleteAllocation deletes an Identity allocation for a handler resource.
func (c ClientArgs) DeleteAllocation(ctx context.Context, resource client.Object) error {
	return identityclient.NewAllocations(c.Client, c.Identity).Delete(ctx, resource)
}
