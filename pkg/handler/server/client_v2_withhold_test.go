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

package server_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/openapi"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func withholdReport(conditionType string) *openapi.ServerProviderCreateGateWithholdAction {
	return &openapi.ServerProviderCreateGateWithholdAction{
		ConditionType: conditionType,
		Reason:        "PoolExhausted",
		Message:       "no partition key is free",
	}
}

func storedServer(ctx context.Context, t *testing.T, k8sClient client.Client, resource *regionv1.Server) *regionv1.Server {
	t.Helper()

	updated := &regionv1.Server{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Namespace: srvNamespace, Name: resource.Name}, updated))

	return updated
}

// A withhold report records the gate False with the satisfier's reason,
// message and identity, and leaves it among the remaining gates, which read
// as the list of gate names they always have.
func TestServerWithholdProviderCreateGate(t *testing.T) {
	t.Parallel()

	c, k8sClient, resource, ctx := newGateClient(t, fabricGate)
	id := idstest.MustParseServerID(resource.Name)
	request := withholdReport(fabricGate)

	require.NoError(t, c.WithholdProviderCreateGate(ctx, id, request))

	status := storedGate(ctx, t, k8sClient, resource, fabricGate)
	require.Equal(t, corev1.ConditionFalse, status.Status)
	require.Equal(t, "pre-create-service", status.Actor)
	require.Equal(t, request.Reason, status.Reason)
	require.Equal(t, request.Message, status.Message)
	require.Empty(t, status.Outputs)
	require.NotZero(t, status.LastTransitionTime)

	result, err := c.GetV2(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, result.Status.RemainingProviderCreateGates)
	require.Equal(t, openapi.ServerRemainingProviderCreateGates{fabricGate}, *result.Status.RemainingProviderCreateGates)
}

// A gate the server was not created with is a 422, as for a satisfying
// report, and nothing is written.
func TestServerWithholdProviderCreateGateRejectsUnknownGate(t *testing.T) {
	t.Parallel()

	c, k8sClient, resource, ctx := newGateClient(t, fabricGate)

	err := c.WithholdProviderCreateGate(ctx, idstest.MustParseServerID(resource.Name), withholdReport("example.unikorn-cloud.org/not-configured"))
	require.Error(t, err)
	require.True(t, coreerrors.IsUnprocessableContent(err), "expected 422 unprocessable content, got: %v", err)
	require.Empty(t, storedServer(ctx, t, k8sClient, resource).Status.ProviderCreateGates)
}

// A satisfied gate cannot be withheld: the server may already be building on
// the strength of it. The report is a 409 and the gate stays True.
func TestServerWithholdProviderCreateGateConflictsOnceSatisfied(t *testing.T) {
	t.Parallel()

	c, k8sClient, resource, ctx := newGateClient(t, fabricGate)
	id := idstest.MustParseServerID(resource.Name)

	require.NoError(t, c.SatisfyProviderCreateGate(ctx, id, gateReport(fabricGate, map[string]string{"pkey": "0x0600"})))

	before := storedServer(ctx, t, k8sClient, resource)

	err := c.WithholdProviderCreateGate(ctx, id, withholdReport(fabricGate))
	require.Error(t, err)
	require.True(t, coreerrors.IsConflict(err), "expected 409 conflict, got: %v", err)

	after := storedServer(ctx, t, k8sClient, resource)
	require.Equal(t, before.ResourceVersion, after.ResourceVersion, "a refused withhold must write nothing")

	status := storedGate(ctx, t, k8sClient, resource, fabricGate)
	require.Equal(t, corev1.ConditionTrue, status.Status)
	require.Equal(t, map[string]string{"pkey": "0x0600"}, status.Outputs)
}

// A withheld gate is pending, not final: a later satisfying report opens it.
func TestServerWithholdThenSatisfyProviderCreateGate(t *testing.T) {
	t.Parallel()

	c, k8sClient, resource, ctx := newGateClient(t, fabricGate)
	id := idstest.MustParseServerID(resource.Name)

	require.NoError(t, c.WithholdProviderCreateGate(ctx, id, withholdReport(fabricGate)))
	require.NoError(t, c.SatisfyProviderCreateGate(ctx, id, gateReport(fabricGate, map[string]string{"pkey": "0x0600"})))

	status := storedGate(ctx, t, k8sClient, resource, fabricGate)
	require.Equal(t, corev1.ConditionTrue, status.Status)
	require.Equal(t, "Prepared", status.Reason)
	require.Equal(t, map[string]string{"pkey": "0x0600"}, status.Outputs)
}

// A satisfier repeating the same withhold on every pass writes nothing after
// the first; a changed reason is written.
func TestServerWithholdProviderCreateGateIsIdempotent(t *testing.T) {
	t.Parallel()

	c, k8sClient, resource, ctx := newGateClient(t, fabricGate)
	id := idstest.MustParseServerID(resource.Name)

	require.NoError(t, c.WithholdProviderCreateGate(ctx, id, withholdReport(fabricGate)))

	before := storedServer(ctx, t, k8sClient, resource)

	require.NoError(t, c.WithholdProviderCreateGate(ctx, id, withholdReport(fabricGate)))
	require.Equal(t, before.ResourceVersion, storedServer(ctx, t, k8sClient, resource).ResourceVersion, "an identical withhold must not write")

	changed := withholdReport(fabricGate)
	changed.Reason = "HostHasNoGUIDs"

	require.NoError(t, c.WithholdProviderCreateGate(ctx, id, changed))

	status := storedGate(ctx, t, k8sClient, resource, fabricGate)
	require.Equal(t, "HostHasNoGUIDs", status.Reason)
	require.Equal(t, corev1.ConditionFalse, status.Status)
}

// Withholding needs the same permission as satisfying: update on the server
// itself is not enough.
func TestServerWithholdProviderCreateGateRequiresPermission(t *testing.T) {
	t.Parallel()

	c, k8sClient, resource, ctx := newGateClient(t, fabricGate)
	ctx = rbac.NewContext(ctx, aclWithSrvUpdate())

	err := c.WithholdProviderCreateGate(ctx, idstest.MustParseServerID(resource.Name), withholdReport(fabricGate))
	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err), "expected forbidden, got: %v", err)
	require.Empty(t, storedServer(ctx, t, k8sClient, resource).Status.ProviderCreateGates)
}

// Every field is required, as on a satisfying report.
func TestServerWithholdProviderCreateGateValidates(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*openapi.ServerProviderCreateGateWithholdAction){
		"conditionType": func(r *openapi.ServerProviderCreateGateWithholdAction) { r.ConditionType = "" },
		"reason":        func(r *openapi.ServerProviderCreateGateWithholdAction) { r.Reason = "" },
		"message":       func(r *openapi.ServerProviderCreateGateWithholdAction) { r.Message = "" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, k8sClient, resource, ctx := newGateClient(t, fabricGate)

			request := withholdReport(fabricGate)
			mutate(request)

			err := c.WithholdProviderCreateGate(ctx, idstest.MustParseServerID(resource.Name), request)
			require.Error(t, err)
			require.True(t, coreerrors.IsBadRequest(err), "expected 400, got: %v", err)
			require.Empty(t, storedServer(ctx, t, k8sClient, resource).Status.ProviderCreateGates)
		})
	}
}
