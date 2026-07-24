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

package conversion

import (
	"time"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/utils/ptr"
)

func ConvertVolumeClasses(regionID regionids.RegionID, in types.VolumeClassList) openapi.VolumeClassListV2Read {
	out := make(openapi.VolumeClassListV2Read, len(in))

	for i := range in {
		out[i] = *convertVolumeClass(regionID, &in[i])
	}

	return out
}

func convertVolumeClass(regionID regionids.RegionID, in *types.VolumeClass) *openapi.VolumeClassV2Read {
	out := &openapi.VolumeClassV2Read{
		Metadata: coreapi.StaticResourceMetadata{
			Id:           in.ID,
			Name:         in.Name,
			CreationTime: time.Unix(0, 0).UTC(),
		},
		Spec: openapi.VolumeClassV2Spec{
			RegionId:  regionID,
			Encrypted: in.Encrypted,
		},
	}

	if in.Description != "" {
		out.Metadata.Description = ptr.To(in.Description)
	}

	if in.Media != "" {
		out.Spec.Media = ptr.To(openapi.VolumeClassV2Media(in.Media))
	}

	if in.Performance != nil {
		out.Spec.Performance = &openapi.VolumeClassV2Performance{
			MaxIOPS:            in.Performance.MaxIOPS,
			MaxThroughputMiBps: in.Performance.MaxThroughput,
		}
	}

	return out
}
