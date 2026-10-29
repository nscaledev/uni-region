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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	mockproviders "github.com/unikorn-cloud/region/pkg/providers/mock"
	"github.com/unikorn-cloud/region/pkg/providers/types"
	mocktypes "github.com/unikorn-cloud/region/pkg/providers/types/mock"
	serverprovisioner "github.com/unikorn-cloud/region/pkg/provisioners/managers/server"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var (
	errNeutronUnreachable = errors.New("neutron unreachable")
	errCAConflict         = errors.New("the object has been modified")
)

// bootedServer is a server that has booted, so it skips the dependency gate.
func bootedServer() *regionv1.Server {
	server := testProvisionServer()
	server.Status.ProvisionedAt = &metav1.Time{Time: time.Now()}

	return server
}

// provisionWith runs one pass of server against a provider whose CreateServer
// returns result and err, and returns the client and the pass's error.
func provisionWith(t *testing.T, server *regionv1.Server, result types.ServerCreateResult, err error, objects ...client.Object) (client.Client, error) {
	t.Helper()

	return provisionDoing(t, server, func(*types.ServerCreateOptions) (types.ServerCreateResult, error) { return result, err }, objects...)
}

// provisionDoing runs one pass of server against a provider whose CreateServer
// runs create, and returns the client and the pass's error.
func provisionDoing(t *testing.T, server *regionv1.Server, create func(*types.ServerCreateOptions) (types.ServerCreateResult, error), objects ...client.Object) (client.Client, error) {
	t.Helper()

	cli := testProvisionClient(t, append(objects, server, testProvisionIdentity())...)

	return cli, provisionOn(t, cli, server, create)
}

// provisionOn runs one pass of server, already stored in cli, against a
// provider whose CreateServer runs create.
func provisionOn(t *testing.T, cli client.Client, server *regionv1.Server, create func(*types.ServerCreateOptions) (types.ServerCreateResult, error)) error {
	t.Helper()

	ctrl := gomock.NewController(t)

	provider := mocktypes.NewMockProvider(ctrl)
	provider.EXPECT().CreateServer(gomock.Any(), gomock.Any(), server, gomock.Any()).DoAndReturn(
		func(_ context.Context, _ *regionv1.Identity, _ *regionv1.Server, options *types.ServerCreateOptions) (types.ServerCreateResult, error) {
			return create(options)
		})

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(testRegionID).Return(provider, nil)

	prov := serverprovisioner.NewForTest(server, providers, nil)

	return prov.Provision(coreclient.NewContext(t.Context(), cli))
}

// TestProvisionReleasesReferencesOnlyOnAConvergedPort pins that references
// follow the provider's report of the port, not the shape of its error. A group
// the spec has just dropped is off the port only once the port has converged:
// released before, its deletion runs into Neutron's "in use"; held after, a
// rebuild that parks or yields for half an hour keeps it undeletable.
func TestProvisionReleasesReferencesOnlyOnAConvergedPort(t *testing.T) {
	t.Parallel()

	converged := types.ServerCreateResult{PortConverged: true}

	for name, tc := range map[string]struct {
		result   types.ServerCreateResult
		err      error
		released bool
	}{
		"converged":                        {result: converged, released: true},
		"converged, then a yield":          {result: converged, err: provisioners.ErrYield, released: true},
		"converged, then a failure":        {result: converged, err: errNeutronUnreachable, released: true},
		"not converged, failure":           {err: coreerrors.ErrResourceNotFound},
		"not converged, cloud unreachable": {err: fmt.Errorf("%w: %w", provisioners.ErrRecheck, errNeutronUnreachable)},
		"not converged, typed outcome":     {err: provisioners.Recheck(unikornv1core.ConditionReasonErrored, "an unexpected error occurred")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := bootedServer()

			reference, err := manager.GenerateResourceReference(testProvisionClient(t), server)
			require.NoError(t, err)

			dropped := &regionv1.SecurityGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "dropped",
					Namespace:  server.Namespace,
					Labels:     map[string]string{constants.IdentityLabel: testIdentityID},
					Finalizers: []string{reference},
				},
			}

			cli, perr := provisionWith(t, server, tc.result, tc.err, dropped)
			require.ErrorIs(t, perr, tc.err)

			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(dropped), dropped))
			require.Equal(t, tc.released, len(dropped.Finalizers) == 0, "finalizers: %v", dropped.Finalizers)
		})
	}
}

// TestProvisionHoldsTheSSHCertificateAuthorityUntilBoot pins the CA reference's
// lifetime. The CA is read only to build the boot's user data, so it is held
// while the stored server has not booted, whatever a pass returned, and
// released on the first pass that starts from a stored boot, whatever the port
// did: released on the pass that only observed the boot, a lost status write
// would leave a CA the user may delete under a create that still needs it. It
// is never taken again: re-adding it every poll writes to a CA many servers
// share.
func TestProvisionHoldsTheSSHCertificateAuthorityUntilBoot(t *testing.T) {
	t.Parallel()

	converged := types.ServerCreateResult{PortConverged: true}

	for name, tc := range map[string]struct {
		booted, holding, boots bool
		result                 types.ServerCreateResult
		err                    error
		held                   bool
	}{
		"before boot":               {result: converged, held: true},
		"before boot, then a yield": {result: converged, err: provisioners.ErrYield, held: true},
		"before boot, then parked":  {result: converged, err: provisioners.ErrTerminal, held: true},
		"boots this pass":           {boots: true, result: converged, held: true},
		"booted, still held":        {booted: true, holding: true, result: converged},
		"booted, port not written":  {booted: true, holding: true, err: provisioners.ErrYield},
		"booted":                    {booted: true, result: converged},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ca := testSSHCertificateAuthority()

			server := testProvisionServer(withTestSSHCertificateAuthority(ca))
			if tc.booted {
				server.Status.ProvisionedAt = &metav1.Time{Time: time.Now()}
			}

			if tc.holding {
				reference, err := manager.GenerateResourceReference(testProvisionClient(t), server)
				require.NoError(t, err)

				ca.Finalizers = []string{reference}
			}

			cli, perr := provisionDoing(t, server, func(*types.ServerCreateOptions) (types.ServerCreateResult, error) {
				if tc.boots {
					server.Status.ProvisionedAt = &metav1.Time{Time: time.Now()}
				}

				return tc.result, tc.err
			}, ca)
			require.ErrorIs(t, perr, tc.err)

			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(ca), ca))
			require.Equal(t, tc.held, len(ca.Finalizers) != 0, "finalizers: %v", ca.Finalizers)

			// The fake client seeds objects at this version: a booted pass with
			// nothing left to release must not write the CA at all.
			if tc.booted && !tc.holding {
				require.Equal(t, "999", ca.ResourceVersion)
			}
		})
	}
}

// TestProvisionReleasesTheSSHCertificateAuthorityBeforeAnythingCanFail pins
// that a booted server's pass releases the CA before anything that can fail
// it: otherwise a server whose identity, say, is broken holds a CA it will
// never read again.
func TestProvisionReleasesTheSSHCertificateAuthorityBeforeAnythingCanFail(t *testing.T) {
	t.Parallel()

	ca := testSSHCertificateAuthority()

	server := testProvisionServer(withTestSSHCertificateAuthority(ca))
	server.Status.ProvisionedAt = &metav1.Time{Time: time.Now()}

	reference, err := manager.GenerateResourceReference(testProvisionClient(t), server)
	require.NoError(t, err)

	ca.Finalizers = []string{reference}

	ctrl := gomock.NewController(t)

	providers := mockproviders.NewMockProviders(ctrl)
	providers.EXPECT().LookupCloud(gomock.Any()).Return(mocktypes.NewMockProvider(ctrl), nil).AnyTimes()

	// No identity, so the pass fails before it reaches the provider.
	cli := testProvisionClient(t, ca, server)

	require.Error(t, serverprovisioner.NewForTest(server, providers, nil).Provision(coreclient.NewContext(t.Context(), cli)))

	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(ca), ca))
	require.Empty(t, ca.Finalizers)
}

// TestProvisionKeepsItsOutcomeWhenTheSSHCertificateAuthorityReleaseFails pins
// that releasing the CA cannot change what a pass reports. Many servers share
// one CA, so the release meets write conflicts, all at once on the upgrade that
// first releases it; returned, each would turn a settled server's pass into a
// yield, showing it provisioning and skipping its generation stamp. The next
// poll retries the release instead.
func TestProvisionKeepsItsOutcomeWhenTheSSHCertificateAuthorityReleaseFails(t *testing.T) {
	t.Parallel()

	for name, outcome := range map[string]error{
		"success": nil,
		"recheck": provisioners.Recheck(unikornv1core.ConditionReasonErrored, "the provider reports the server in an error state"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ca := testSSHCertificateAuthority()

			server := testProvisionServer(withTestSSHCertificateAuthority(ca))
			server.Status.ProvisionedAt = &metav1.Time{Time: time.Now()}

			reference, err := manager.GenerateResourceReference(testProvisionClient(t), server)
			require.NoError(t, err)

			ca.Finalizers = []string{reference}

			conflict := func(ctx context.Context, cli client.WithWatch, object client.Object, opts ...client.UpdateOption) error {
				if _, ok := object.(*regionv1.SSHCertificateAuthority); ok {
					return kerrors.NewConflict(schema.GroupResource{}, object.GetName(), errCAConflict)
				}

				return cli.Update(ctx, object, opts...)
			}

			cli := testProvisionClientWithInterceptor(t, interceptor.Funcs{Update: conflict}, ca, server, testProvisionIdentity())

			perr := provisionOn(t, cli, server, func(*types.ServerCreateOptions) (types.ServerCreateResult, error) {
				return types.ServerCreateResult{PortConverged: true}, outcome
			})

			if outcome == nil {
				require.NoError(t, perr)
			} else {
				require.Equal(t, outcome, perr)
			}

			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(ca), ca))
			require.Equal(t, []string{reference}, ca.Finalizers, "still held, for the next poll to release")
		})
	}
}

// TestProvisionToleratesADeletedSSHCertificateAuthorityAfterBoot pins that a CA
// deleted once nothing holds it does not fail a booted server: the reference
// was released after boot, so the user may delete it. A server Nova lost is then
// re-created without the CA part.
func TestProvisionToleratesADeletedSSHCertificateAuthorityAfterBoot(t *testing.T) {
	t.Parallel()

	ca := testSSHCertificateAuthority()

	server := testProvisionServer(withTestSSHCertificateAuthority(ca))
	server.Status.ProvisionedAt = &metav1.Time{Time: time.Now()}

	var options *types.ServerCreateOptions

	_, err := provisionDoing(t, server, func(o *types.ServerCreateOptions) (types.ServerCreateResult, error) {
		options = o

		return types.ServerCreateResult{PortConverged: true}, nil
	})
	require.NoError(t, err)
	require.Equal(t, server.Spec.UserData, options.UserData, "no CA part")
}

// TestServerCreateOptionsMissingSSHCertificateAuthority pins the boot rule in
// the create options themselves. A whole pass cannot: before boot the reference
// add meets the missing CA first.
func TestServerCreateOptionsMissingSSHCertificateAuthority(t *testing.T) {
	t.Parallel()

	ca := testSSHCertificateAuthority()
	cli := testProvisionClient(t)

	creating := testProvisionServer(withTestSSHCertificateAuthority(ca))

	_, err := serverprovisioner.ServerCreateOptionsForTest(t.Context(), creating, cli)
	require.True(t, kerrors.IsNotFound(err), "before boot a missing CA is a fault: %v", err)

	booted := testProvisionServer(withTestSSHCertificateAuthority(ca))
	booted.Status.ProvisionedAt = &metav1.Time{Time: time.Now()}

	options, err := serverprovisioner.ServerCreateOptionsForTest(t.Context(), booted, cli)
	require.NoError(t, err)
	require.Equal(t, booted.Spec.UserData, options.UserData, "no CA part")
}
