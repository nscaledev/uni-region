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

package identity_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/identity"

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
	identityID     = "baz"
	reference      = "cat"
)

// setupFixtures sets up all the required apparatus to actually test
// anything, proving how annoying organization namespaces are!
func setupFixtures(t *testing.T) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, regionv1.AddToScheme(scheme))

	identity := &regionv1.Identity{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      identityID,
			Labels: map[string]string{
				constants.OrganizationLabel: organizationID,
				constants.ProjectLabel:      projectID,
			},
		},
	}

	objects := []client.Object{
		identity,
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func getIdentity(t *testing.T, cli client.Client) *regionv1.Identity {
	t.Helper()

	identity := &regionv1.Identity{}

	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: identityID}, identity))

	return identity
}

// TestReferences tests reference creation and deletion works and is idempotent.
func TestReferences(t *testing.T) {
	t.Parallel()

	cli := setupFixtures(t)

	client := identity.New(cli, namespace)

	// Create succeeds.
	require.NoError(t, client.ReferenceCreate(t.Context(), organizationID, projectID, identityID, reference))

	identity := getIdentity(t, cli)
	require.Len(t, identity.Finalizers, 1)
	require.True(t, controllerutil.ContainsFinalizer(identity, reference))

	// Create as second time succeeds.
	require.NoError(t, client.ReferenceCreate(t.Context(), organizationID, projectID, identityID, reference))

	identity = getIdentity(t, cli)
	require.Len(t, identity.Finalizers, 1)
	require.True(t, controllerutil.ContainsFinalizer(identity, reference))

	// Delete succeeds.
	require.NoError(t, client.ReferenceDelete(t.Context(), organizationID, projectID, identityID, reference))

	identity = getIdentity(t, cli)
	require.Empty(t, identity.Finalizers)

	// Delete a second time succeeds.
	require.NoError(t, client.ReferenceDelete(t.Context(), organizationID, projectID, identityID, reference))

	identity = getIdentity(t, cli)
	require.Empty(t, identity.Finalizers)
}
