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

package network_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/network"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	namespace      = "base"
	organizationID = "foo"
	projectID      = "bar"
	networkID      = "baz"
	reference      = "cat"
)

// setupFixtures sets up all the required apparatus to actually test
// anything, proving how annoying organization namespaces are!
func setupFixtures(t *testing.T) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, regionv1.AddToScheme(scheme))

	network := &regionv1.Network{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      networkID,
			Labels: map[string]string{
				coreconstants.OrganizationLabel:   organizationID,
				coreconstants.ProjectLabel:        projectID,
				constants.ResourceAPIVersionLabel: "2",
			},
		},
	}

	objects := []client.Object{
		network,
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func getNetwork(t *testing.T, cli client.Client) *regionv1.Network {
	t.Helper()

	network := &regionv1.Network{}

	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: networkID}, network))

	return network
}

// TestReferences tests reference creation and deletion works and is idempotent.
func TestReferences(t *testing.T) {
	t.Parallel()

	acl := &identityapi.Acl{
		Global: &identityapi.AclEndpoints{
			{
				Name: "region:networks:v2",
				Operations: identityapi.AclOperations{
					identityapi.Read,
				},
			},
			{
				Name: "region:networks:v2/references",
				Operations: identityapi.AclOperations{
					identityapi.Create,
					identityapi.Delete,
				},
			},
		},
	}

	ctx := rbac.NewContext(t.Context(), acl)

	cli := setupFixtures(t)

	clientArgs := common.ClientArgs{
		Client:    cli,
		Namespace: namespace,
	}

	client := network.New(clientArgs)

	// Create succeeds.
	require.NoError(t, client.ReferenceCreateV2(ctx, networkID, reference))

	network := getNetwork(t, cli)
	require.Len(t, network.Finalizers, 1)
	require.True(t, controllerutil.ContainsFinalizer(network, reference))

	// Create as second time succeeds.
	require.NoError(t, client.ReferenceCreateV2(ctx, networkID, reference))

	network = getNetwork(t, cli)
	require.Len(t, network.Finalizers, 1)
	require.True(t, controllerutil.ContainsFinalizer(network, reference))

	// Delete succeeds.
	require.NoError(t, client.ReferenceDeleteV2(ctx, networkID, reference))

	network = getNetwork(t, cli)
	require.Empty(t, network.Finalizers)

	// Delete a second time succeeds.
	require.NoError(t, client.ReferenceDeleteV2(ctx, networkID, reference))

	network = getNetwork(t, cli)
	require.Empty(t, network.Finalizers)
}
