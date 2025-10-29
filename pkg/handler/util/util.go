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
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ForegroundDeleteOptions() *client.DeleteOptions {
	return &client.DeleteOptions{
		PropagationPolicy: ptr.To(metav1.DeletePropagationForeground),
	}
}

func addQuery(selector labels.Selector, label string, vals []string) labels.Selector {
	if len(vals) == 0 {
		return selector
	}

	if len(vals) == 1 {
		// SM: Send me to burn in hell, but the client code is way
		// prettier, we're basically pulling the checks out of the library.
		req, _ := labels.NewRequirement(label, selection.Equals, vals)

		return selector.Add(*req)
	}

	req, _ := labels.NewRequirement(label, selection.In, vals)

	return selector.Add(*req)
}

func AddRegionIDQuery(selector labels.Selector, query *openapi.RegionIDQueryParameter) labels.Selector {
	if query == nil {
		return selector
	}

	return addQuery(selector, constants.RegionLabel, *query)
}

func AddProjectIDQuery(selector labels.Selector, query *openapi.ProjectIDQueryParameter) labels.Selector {
	if query == nil {
		return selector
	}

	return addQuery(selector, coreconstants.ProjectLabel, *query)
}

func AddNetworkIDQuery(selector labels.Selector, query *openapi.NetworkIDQueryParameter) labels.Selector {
	if query == nil {
		return selector
	}

	return addQuery(selector, constants.NetworkLabel, *query)
}
