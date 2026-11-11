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
)

func TestVolumeMockExercisesLifecycleContract(t *testing.T) {
	t.Parallel()

	controller := gomock.NewController(t)
	provider := mock.NewMockVolume(controller)
	identity := &unikornv1.Identity{}
	volume := &unikornv1.Volume{}

	provider.EXPECT().CreateVolume(t.Context(), identity, volume).Return(nil)
	provider.EXPECT().DeleteVolume(t.Context(), identity, volume).Return(nil)

	provider.EXPECT().UpdateVolumeState(t.Context(), identity, volume).DoAndReturn(func(_ any, _ any, got *unikornv1.Volume) error { return nil })

	var capability types.Volume = provider

	if err := capability.CreateVolume(t.Context(), identity, volume); err != nil {
		t.Fatalf("CreateVolume() error = %v", err)
	}

	if err := capability.DeleteVolume(t.Context(), identity, volume); err != nil {
		t.Fatalf("DeleteVolume() error = %v", err)
	}

	if err := capability.UpdateVolumeState(t.Context(), identity, volume); err != nil {
		t.Fatalf("UpdateVolumeState() error = %v", err)
	}
}
