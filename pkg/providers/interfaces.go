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

//go:generate mockgen -source=interfaces.go -destination=mock/interfaces.go -package=mock
package providers

import (
	"context"

	"github.com/unikorn-cloud/region/pkg/providers/types"
)

type Providers interface {
	// LookupCommon returns a provider as identified by the region ID of any type.
	LookupCommon(ctx context.Context, regionID string) (types.CommonProvider, error)
	// LookupCloud returns a provider as identified by the region ID and must be
	// a cloud type.
	LookupCloud(ctx context.Context, regionID string) (types.Provider, error)
}
