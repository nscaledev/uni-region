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

//nolint:testpackage
package openstack

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingKeystone is an identity service that serves a minimal v3 token and
// counts the password grants it is asked for.
type countingKeystone struct {
	server *httptest.Server
	grants atomic.Int64
}

func newCountingKeystone(t *testing.T) *countingKeystone {
	t.Helper()

	return newKeystone(t, nil)
}

// newKeystone builds an identity service that counts grants and, if before is
// non-nil, runs it inside the handler before answering.
func newKeystone(t *testing.T, before func()) *countingKeystone {
	t.Helper()

	keystone := &countingKeystone{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, _ *http.Request) {
		keystone.grants.Add(1)

		if before != nil {
			before()
		}

		// Versioned catalog URLs, as a real cloud publishes them: gophercloud
		// reads the version from the URL rather than probing the endpoint.
		compute := keystone.server.URL + "/compute/v2.1"
		network := keystone.server.URL + "/network/v2.0"

		w.Header().Set("X-Subject-Token", "token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token":{"expires_at":%q,"catalog":[`+
			`{"id":"c","name":"nova","type":"compute",`+
			`"endpoints":[{"id":"ce","interface":"public","region":"","url":%q}]},`+
			`{"id":"n","name":"neutron","type":"network",`+
			`"endpoints":[{"id":"ne","interface":"public","region":"","url":%q}]}]}}`,
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339), compute, network)
	})

	keystone.server = httptest.NewServer(mux)
	t.Cleanup(keystone.server.Close)

	return keystone
}

func (k *countingKeystone) endpoint() string {
	return k.server.URL + "/v3/"
}

// TestSessionSharesOneLoginPerCredential pins the property the resync depends
// on: a login is paid per credential, not per client. Every New*Client used to
// be a full AuthenticatedClient — a password grant plus a catalog fetch — of
// which a reconcile builds two or three, so an identity holding a thousand
// servers paid a couple of thousand grants to learn the same thing.
//
// Sequential rather than concurrent on purpose: this asserts the client is
// retained, which is what stops the next herd paying again. The single-flight
// that collapses a simultaneous cold start is pinned by
// TestSessionCollapsesConcurrentLogins.
func TestSessionSharesOneLoginPerCredential(t *testing.T) {
	t.Parallel()

	keystone := newCountingKeystone(t)

	const reconciles = 50

	for range reconciles {
		// What a reconcile does: a network client and a compute client, each of
		// which used to be its own login.
		_, err := NewNetworkClient(t.Context(), NewPasswordProvider(keystone.endpoint(), "user", "secret", t.Name()), nil)
		require.NoError(t, err)

		_, err = NewComputeClient(t.Context(), NewPasswordProvider(keystone.endpoint(), "user", "secret", t.Name()), nil)
		require.NoError(t, err)
	}

	assert.Equal(t, int64(1), keystone.grants.Load(),
		"%d reconciles on one credential must pay one login", reconciles)
}

// TestSessionDoesNotShareAcrossCredentials pins the other half: caching a client
// must not serve one credential's client to another. A pinned server reads its
// project as the Region admin user while a tenant server reads the same project
// as its own service principal, and those two must stay separate.
func TestSessionDoesNotShareAcrossCredentials(t *testing.T) {
	t.Parallel()

	keystone := newCountingKeystone(t)

	for _, project := range []string{"project-a", "project-b"} {
		for _, user := range []string{"region-admin", "service-principal"} {
			_, err := NewComputeClient(t.Context(),
				NewPasswordProvider(keystone.endpoint(), user, "secret", project), nil)
			require.NoError(t, err)
		}
	}

	assert.Equal(t, int64(4), keystone.grants.Load(),
		"each distinct credential must log in for itself")
}

// blockingKeystone is an identity service that parks every grant until released,
// so a test can hold a login open and watch what other callers do.
type blockingKeystone struct {
	*countingKeystone
	arrived chan struct{}
	release chan struct{}
}

func newBlockingKeystone(t *testing.T) *blockingKeystone {
	t.Helper()

	keystone := &blockingKeystone{
		arrived: make(chan struct{}, 1),
		release: make(chan struct{}),
	}

	keystone.countingKeystone = newKeystone(t, func() {
		select {
		case keystone.arrived <- struct{}{}:
		default:
		}

		<-keystone.release
	})

	return keystone
}

// TestSessionCollapsesConcurrentLogins pins the property a controller restart
// depends on: a herd arriving on a cold credential pays one grant between them,
// not one each. Nothing is cached at the moment a resync wakes every server, so
// this is exactly when the credential is asked for a thousand times over.
//
// Deterministic because the identity service holds the first grant open until the
// test releases it: while it is held, every other caller must be waiting on that
// one flight rather than opening its own.
func TestSessionCollapsesConcurrentLogins(t *testing.T) {
	t.Parallel()

	const callers = 200

	keystone := newBlockingKeystone(t)

	var done sync.WaitGroup

	done.Add(callers)

	errs := make([]error, callers)

	for i := range callers {
		go func() {
			defer done.Done()

			_, errs[i] = NewPasswordProvider(keystone.endpoint(), "user", "secret", t.Name()).Client(t.Context())
		}()
	}

	// The grant is now open and stays open until released, so any caller that was
	// going to log in for itself has to do it against this same server.
	<-keystone.arrived

	close(keystone.release)
	done.Wait()

	assert.Equal(t, int64(1), keystone.grants.Load(),
		"%d callers on one cold credential must pay one grant", callers)

	for i := range callers {
		assert.NoError(t, errs[i], "every caller must be served the shared client")
	}
}

// TestSessionAuthenticateHonoursCallerContext pins the escape hatch the design
// rests on: a caller waiting on someone else's login is not held by it. A leader
// whose grant wedges against an unresponsive Keystone must not take the callers
// behind it down, which would otherwise include the synchronous API handlers that
// share a credential with the reconciler and the monitor.
//
// The leader is a real login on the same registry session the caller reaches, so
// the caller genuinely joins the flight rather than leading one of its own.
func TestSessionAuthenticateHonoursCallerContext(t *testing.T) {
	t.Parallel()

	keystone := newBlockingKeystone(t)
	defer close(keystone.release)

	credential := NewPasswordProvider(keystone.endpoint(), "user", "secret", t.Name())

	go func() {
		_, _ = credential.Client(t.Context())
	}()

	// The login is open and will not return until the deferred release.
	<-keystone.arrived

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := credential.Client(ctx)
	require.ErrorIs(t, err, context.Canceled,
		"a caller must abandon a login its own context outlived")
}

// TestSessionLoginSurvivesLeaderCancellation pins the other half: one caller
// giving up must not fail the callers that joined its flight. An API handler whose
// client hangs up can be the first to ask for a cold credential, and the healthy
// reconciles behind it would each have logged in perfectly well.
func TestSessionLoginSurvivesLeaderCancellation(t *testing.T) {
	t.Parallel()

	keystone := newBlockingKeystone(t)

	credential := NewPasswordProvider(keystone.endpoint(), "user", "secret", t.Name())

	leaderCtx, cancelLeader := context.WithCancel(t.Context())

	leaderDone := make(chan error, 1)

	go func() {
		_, err := credential.Client(leaderCtx)
		leaderDone <- err
	}()

	<-keystone.arrived

	// The leader walks away while its login is still in flight.
	cancelLeader()
	require.ErrorIs(t, <-leaderDone, context.Canceled)

	close(keystone.release)

	client, err := credential.Client(t.Context())
	require.NoError(t, err, "a healthy caller must not inherit the leader's cancellation")
	require.NotNil(t, client)

	assert.Equal(t, int64(1), keystone.grants.Load(),
		"the abandoned login must still have populated the cache")
}

// TestSessionBoundsProviderRequests pins that the shared client carries a
// timeout. Sharing the client shares gophercloud's reauth serialisation, which
// waits for an in-progress refresh on every request without consulting a context,
// so an unbounded client would let one hung refresh park every caller on the
// credential.
func TestSessionBoundsProviderRequests(t *testing.T) {
	t.Parallel()

	keystone := newCountingKeystone(t)

	client, err := NewPasswordProvider(keystone.endpoint(), "user", "secret", t.Name()).Client(t.Context())
	require.NoError(t, err)

	assert.Equal(t, providerRequestTimeout, client.HTTPClient.Timeout,
		"a shared client must bound its own requests")
}

// TestSessionBoundsTheLoginItself pins that the timeout is in place BEFORE
// authenticating, which is not interchangeable with setting it afterwards.
// gophercloud copies the client by value to build the one it reauthenticates
// with, so a timeout assigned after the login leaves both the login and every
// later reauth unbounded — and the reauth is the request every other caller on
// the credential waits behind.
//
//nolint:paralleltest // shortens the package-level bound, so it cannot run alongside others.
func TestSessionBoundsTheLoginItself(t *testing.T) {
	previous := providerRequestTimeout
	providerRequestTimeout = 50 * time.Millisecond

	defer func() { providerRequestTimeout = previous }()

	keystone := newBlockingKeystone(t)
	defer close(keystone.release)

	_, err := NewPasswordProvider(keystone.endpoint(), "user", "secret", t.Name()).Client(t.Context())
	require.Error(t, err, "an unresponsive identity service must not hang the login")
	assert.NotErrorIs(t, err, context.Canceled, "it must fail on its own timeout, not a context")
}
