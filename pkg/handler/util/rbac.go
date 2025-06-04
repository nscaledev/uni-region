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
	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AssertOrganizationOwnership checks whether the resource has the correct
// organizationID.  When we call an API the RBAC layer asserts that the user
// provided organizationID is allowable for the actor making the call.  However
// for GET APIs it's quicker and easier to directly get an object by ID, rather
// than do a full list lookup with a full set of label selectors.  This does
// however mean that a user can ostensibly read any resource if it knows the ID.
// Ensure we return a 404 here on error so we don't give away any facts about
// resources that shoudn't be visible to the client.
func AssertOrganizationOwnership(resource metav1.Object, organizationID string) error {
	labels := resource.GetLabels()

	id, ok := labels[constants.OrganizationLabel]
	if !ok {
		return errors.OAuth2ServerError("resource missing organization label")
	}

	if id != organizationID {
		return errors.HTTPNotFound()
	}

	return nil
}

// AssertProjectOwnership does the same as AssertOrganizationOwnership but with
// additional project scoping.
func AssertProjectOwnership(resource metav1.Object, organizationID, projectID string) error {
	if err := AssertOrganizationOwnership(resource, organizationID); err != nil {
		return err
	}

	labels := resource.GetLabels()

	id, ok := labels[constants.ProjectLabel]
	if !ok {
		return errors.OAuth2ServerError("resource missing organization label")
	}

	if id != projectID {
		return errors.HTTPNotFound()
	}

	return nil
}
