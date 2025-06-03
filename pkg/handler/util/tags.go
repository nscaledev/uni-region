/*
Copyright 2025 the Unikorn Authors.

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

package util

import (
	"strings"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/openapi"
)

func DecodeTagSelectorParam(tags *openapi.TagSelectorParameter) (unikornv1core.TagList, error) {
	if tags == nil {
		return nil, nil
	}

	out := make(unikornv1core.TagList, len(*tags))

	for i, tag := range *tags {
		parts := strings.Split(tag, "=")
		if len(parts) != 2 {
			return nil, errors.OAuth2InvalidRequest("tag decode failed")
		}

		out[i] = unikornv1core.Tag{
			Name:  parts[0],
			Value: parts[1],
		}
	}

	return out, nil
}
