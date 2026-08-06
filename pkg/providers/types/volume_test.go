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
	"testing"

	"go.uber.org/mock/gomock"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	"github.com/unikorn-cloud/region/pkg/providers/types/mock"

	"k8s.io/apimachinery/pkg/api/resource"
)

func TestVolumeMockExercisesLifecycleContract(t *testing.T) {
	t.Parallel()

	controller := gomock.NewController(t)
	provider := mock.NewMockVolume(controller)
	identity := &unikornv1.Identity{}
	volume := &unikornv1.Volume{}

	provider.EXPECT().CreateVolume(t.Context(), identity, volume).Return(nil)
	provider.EXPECT().DeleteVolume(t.Context(), identity, volume).Return(nil)

	observation := &types.VolumeObservation{
		Size:   resource.MustParse("20Gi"),
		Status: types.VolumeStatusAvailable,
	}
	provider.EXPECT().ObserveVolume(t.Context(), identity, volume).Return(observation, nil)

	var capability types.Volume = provider

	if err := capability.CreateVolume(t.Context(), identity, volume); err != nil {
		t.Fatalf("CreateVolume() error = %v", err)
	}

	if err := capability.DeleteVolume(t.Context(), identity, volume); err != nil {
		t.Fatalf("DeleteVolume() error = %v", err)
	}

	got, err := capability.ObserveVolume(t.Context(), identity, volume)
	if err != nil {
		t.Fatalf("ObserveVolume() error = %v", err)
	}

	if got != observation {
		t.Fatalf("ObserveVolume() = %#v, want %#v", got, observation)
	}
}
