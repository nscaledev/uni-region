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

package volume_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	volume "github.com/unikorn-cloud/region/pkg/managers/volume"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	volumeprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/volume"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestFactoryWiresVolumeProvisioner(t *testing.T) {
	t.Parallel()

	factory := &volume.Factory{}
	options := factory.Options()
	require.IsType(t, &volumeprovisioner.Options{}, options)

	scheme := runtime.NewScheme()
	for _, addToScheme := range factory.Schemes() {
		require.NoError(t, addToScheme(scheme))
	}

	kinds, _, err := scheme.ObjectKinds(&unikornv1.Volume{})
	require.NoError(t, err)
	require.Contains(t, kinds, unikornv1.SchemeGroupVersion.WithKind("Volume"))

	providerSet := mockproviders.NewMockProviders(gomock.NewController(t))
	provisioner := volumeprovisioner.New(options, providerSet)
	require.IsType(t, &unikornv1.Volume{}, provisioner.Object())
}

func TestVolumeDeletionRequested(t *testing.T) {
	t.Parallel()

	oldVolume := &unikornv1.Volume{}
	deletingVolume := oldVolume.DeepCopy()
	now := metav1.Now()
	deletingVolume.DeletionTimestamp = &now

	require.True(t, volume.VolumeDeletionRequestedForTest(event.TypedUpdateEvent[*unikornv1.Volume]{
		ObjectOld: oldVolume,
		ObjectNew: deletingVolume,
	}))
	require.False(t, volume.VolumeDeletionRequestedForTest(event.TypedUpdateEvent[*unikornv1.Volume]{
		ObjectOld: oldVolume,
		ObjectNew: oldVolume.DeepCopy(),
	}))
}
