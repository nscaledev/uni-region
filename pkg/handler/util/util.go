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
	"context"

	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ForegroundDeleteOptions() *client.DeleteOptions {
	return &client.DeleteOptions{
		PropagationPolicy: ptr.To(metav1.DeletePropagationForeground),
	}
}

func OrganizationIDQuery(query *openapi.OrganizationIDQueryParameter) []string {
	if query == nil {
		return nil
	}

	return *query
}

func ProjectIDQuery(query *openapi.ProjectIDQueryParameter) []string {
	if query == nil {
		return nil
	}

	return *query
}

func AddRegionIDQuery(selector labels.Selector, query *openapi.RegionIDQueryParameter) (labels.Selector, error) {
	if query == nil {
		return selector, nil
	}

	return rbac.AddQuery(selector, constants.RegionLabel, *query)
}

func AddNetworkIDQuery(selector labels.Selector, query *openapi.NetworkIDQueryParameter) (labels.Selector, error) {
	if query == nil {
		return selector, nil
	}

	return rbac.AddQuery(selector, constants.NetworkLabel, *query)
}

// InjectUserPrincipal updates the principal information from either the resource request
// or the existing resource.
func InjectUserPrincipal(ctx context.Context, organizationID, projectID string) error {
	principal, err := principal.FromContext(ctx)
	if err != nil {
		return err
	}

	if principal.OrganizationID == "" {
		principal.OrganizationID = organizationID
		principal.ProjectID = projectID
	}

	return nil
}
