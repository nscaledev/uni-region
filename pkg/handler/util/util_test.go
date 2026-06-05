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

package util_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestInjectUserPrincipalMissingPrincipalReturnsError(t *testing.T) {
	t.Parallel()

	err := util.InjectUserPrincipal(t.Context(), "org-id", "project-id")
	require.Error(t, err)
	require.ErrorIs(t, err, coreerrors.ErrInvalidContext)
}

func TestInjectUserPrincipalSetsFieldsWhenOrganizationEmpty(t *testing.T) {
	t.Parallel()

	p := &principal.Principal{Actor: "actor@example.com"}
	ctx := principal.NewContext(t.Context(), p)

	err := util.InjectUserPrincipal(ctx, "org-id", "project-id")
	require.NoError(t, err)

	got, err := principal.FromContext(ctx)
	require.NoError(t, err)
	require.Equal(t, "org-id", got.OrganizationID)
	require.Equal(t, "project-id", got.ProjectID)
}

func TestInjectUserPrincipalDoesNotOverwriteExistingOrganization(t *testing.T) {
	t.Parallel()

	p := &principal.Principal{
		OrganizationID: "existing-org",
		ProjectID:      "existing-project",
	}
	ctx := principal.NewContext(t.Context(), p)

	err := util.InjectUserPrincipal(ctx, "request-org", "request-project")
	require.NoError(t, err)

	got, err := principal.FromContext(ctx)
	require.NoError(t, err)
	require.Equal(t, "existing-org", got.OrganizationID)
	require.Equal(t, "existing-project", got.ProjectID)
}

func TestOrganizationIDQueryNilReturnsNil(t *testing.T) {
	t.Parallel()

	require.Nil(t, util.OrganizationIDQuery(nil))
}

func TestOrganizationIDQueryReturnsUnwrappedSlice(t *testing.T) {
	t.Parallel()

	query := openapi.OrganizationIDQueryParameter{"org-a", "org-b"}
	require.Equal(t, []string{"org-a", "org-b"}, util.OrganizationIDQuery(&query))
}

func TestProjectIDQueryNilReturnsNil(t *testing.T) {
	t.Parallel()

	require.Nil(t, util.ProjectIDQuery(nil))
}

func TestProjectIDQueryReturnsUnwrappedSlice(t *testing.T) {
	t.Parallel()

	query := openapi.ProjectIDQueryParameter{"project-a", "project-b"}
	require.Equal(t, []string{"project-a", "project-b"}, util.ProjectIDQuery(&query))
}

func TestAddRegionIDQueryNilLeavesSelectorUnchanged(t *testing.T) {
	t.Parallel()

	selector := labels.NewSelector()

	got, err := util.AddRegionIDQuery(selector, nil)
	require.NoError(t, err)
	require.Equal(t, selector.String(), got.String())
}

func TestAddRegionIDQueryAddsRegionLabelRequirement(t *testing.T) {
	t.Parallel()

	query := openapi.RegionIDQueryParameter{"region-id"}

	got, err := util.AddRegionIDQuery(labels.NewSelector(), &query)
	require.NoError(t, err)
	require.Contains(t, got.String(), constants.RegionLabel)
	require.Contains(t, got.String(), "region-id")
}

func TestAddNetworkIDQueryNilLeavesSelectorUnchanged(t *testing.T) {
	t.Parallel()

	selector := labels.NewSelector()

	got, err := util.AddNetworkIDQuery(selector, nil)
	require.NoError(t, err)
	require.Equal(t, selector.String(), got.String())
}

func TestAddNetworkIDQueryAddsNetworkLabelRequirement(t *testing.T) {
	t.Parallel()

	query := openapi.NetworkIDQueryParameter{"network-id"}

	got, err := util.AddNetworkIDQuery(labels.NewSelector(), &query)
	require.NoError(t, err)
	require.Contains(t, got.String(), constants.NetworkLabel)
	require.Contains(t, got.String(), "network-id")
}

func TestForegroundDeleteOptionsSetsForegroundPropagation(t *testing.T) {
	t.Parallel()

	opts := util.ForegroundDeleteOptions()
	require.NotNil(t, opts.PropagationPolicy)
	require.Equal(t, metav1.DeletePropagationForeground, *opts.PropagationPolicy)
}
