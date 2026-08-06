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

package providers_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
)

type volumeProvider struct {
	types.CommonProvider
	types.Volume
}

func TestLookupVolume(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	common := mocktypes.NewMockCommonProvider(ctrl)
	volume := mocktypes.NewMockVolume(ctrl)
	providerSet := providers.NewCachedForTest(map[string]types.CommonProvider{
		"supported": volumeProvider{
			CommonProvider: common,
			Volume:         volume,
		},
		"unsupported": common,
	})

	got, err := providerSet.LookupVolume("supported")
	require.NoError(t, err)

	identity := &unikornv1.Identity{}
	resource := &unikornv1.Volume{}
	volume.EXPECT().CreateVolume(gomock.Any(), identity, resource).Return(nil)
	require.NoError(t, got.CreateVolume(t.Context(), identity, resource))

	_, err = providerSet.LookupVolume("unsupported")
	require.ErrorIs(t, err, providers.ErrRegionWrongKind)
}
