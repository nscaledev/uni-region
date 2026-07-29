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

package types_test

import (
	"context"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/resource"
)

// volumeContract pins the lifecycle boundary consumed by the Volume controller
// and monitor without coupling those consumers to provider SDK types.
type volumeContract interface {
	CreateVolume(context.Context, *unikornv1.Identity, *unikornv1.Volume) error
	FindVolume(context.Context, *unikornv1.Identity, *unikornv1.Volume) (bool, error)
	ObserveVolume(context.Context, *unikornv1.Identity, *unikornv1.Volume) (*types.VolumeState, error)
	DeleteVolume(context.Context, *unikornv1.Identity, *unikornv1.Volume) error
}

var _ volumeContract = (types.Volume)(nil)

var _ = types.VolumeState{
	Size:   resource.MustParse("64Gi"),
	Status: types.VolumeStatusAvailable,
}
