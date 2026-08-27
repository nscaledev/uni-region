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

package openstack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"golang.org/x/sync/singleflight"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
)

// providerRequestTimeout bounds any single request made with a shared provider
// client. Generous enough for a slow list over a large project, short enough
// that a black-holed connection cannot wedge a credential indefinitely.
//
// It exists because sharing a client shares gophercloud's reauth serialisation:
// AuthenticatedHeaders waits on an in-progress reauth for EVERY request, on a
// channel receive that consults no context. One caller whose token refresh hangs
// against an unresponsive Keystone would otherwise park every other caller on
// that credential — reconciles, the monitor, and the synchronous reboot, start,
// stop and console handlers — below the level at which their own contexts could
// rescue them. Before the client was shared, a hung login cost one goroutine. A
// zero-value http.Client has no timeout at all, so the bound has to be set
// explicitly or it does not exist.
//
// Note this bounds a single request, not a single call. One call can serialise a
// context-free wait on somebody else's in-progress reauth, its own request, a
// reauth on a 401, and the retry — so the worst case a caller can observe is
// several multiples of this. A cold login against a versionless Keystone endpoint
// is likewise two bounded requests, discovery and the token grant.
//
// A var, not a const, only so tests can shorten it.
//
//nolint:gochecknoglobals
var providerRequestTimeout = 60 * time.Second

// Session is the state shared by every service client built from one credential,
// and it outlives all of them.
//
// It exists because a credential's callers arrive in herds. Every New*Client was
// a full AuthenticatedClient — a password grant plus a service catalog fetch —
// and a reconcile builds two or three. Meanwhile a pinned server authenticates as
// the Region admin user scoped to the service principal's project rather than as
// the tenant service principal, so every server pinned to one identity shares one
// credential. A restart resync of an identity holding 1157 servers asked for that
// one credential a couple of thousand times inside a few minutes, and the health
// monitor asked for it again for every server, every minute.
//
// So the authenticated ProviderClient is cached, and concurrent cold starts are
// collapsed to a single login. The client that comes back holds the token,
// carries ReauthFunc and serialises its own reauth internally, so it refreshes in
// place and needs no expiry tracking here. Caching the derived service clients
// instead would synchronise token expiry across a burst — everything built in one
// burst expiring in one burst — and rebuild the herd an hour later.
//
// Two consequences are worth knowing.
//
// Caching the client pins the service catalog for the life of the process.
// gophercloud's v3auth closes EndpointLocator over the catalog from the login
// that built the client, and ReauthFunc only copies the refreshed token back, not
// a new catalog. So every service client built from a cached ProviderClient
// resolves endpoints from the snapshot taken at first login: if an operator moves
// a service's public endpoint in Keystone, this process keeps calling the old URL
// until it restarts, where previously each client construction re-fetched the
// catalog and self-healed within a reconcile.
//
// A reauth failure does not poison the client durably. gophercloud clears its
// reauth mutex on the way out and tracks the attempt per request, so a disabled
// credential fails per request and recovers on its own once fixed.
//
// The reauth is not detached, though, and that asymmetry is worth knowing. This
// package controls the context of the cold-start login and runs it detached;
// gophercloud controls the reauth and runs it under whichever caller's request
// happened to receive the 401, handing that one result to every caller which hit
// a 401 at the same moment. So at token expiry the failure this package took care
// to avoid at cold start reappears in a smaller form: an API handler whose client
// hangs up mid-refresh gives its cancellation to the other callers refreshing
// alongside it. They surface an error and retry, and it self-heals on the next
// pass, so the cost is a spurious failure rather than a stuck credential — but it
// is a consequence of sharing the client that did not exist when every caller
// refreshed its own.
type Session struct {
	// login collapses concurrent cold-start logins on this credential.
	login singleflight.Group

	lock   sync.Mutex
	client *gophercloud.ProviderClient
}

// cached returns the shared client, or nil if nobody has logged in yet.
func (s *Session) cached() *gophercloud.ProviderClient {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.client
}

// authenticate returns the client shared by every caller using this credential,
// logging in at most once however many callers arrive together.
//
// Every caller keeps its own context, and the login itself keeps none of them.
// singleflight.Do would park a follower on a WaitGroup it cannot interrupt, so a
// leader whose login wedged would hold every caller behind it; DoChan lets a
// caller stop waiting the moment its own context is done, whatever the login is
// still doing. The login runs detached and is bounded only by the client's
// request timeout, so no caller's cancellation can fail the herd it happens to
// be leading, and work already paid for is not thrown away.
func (s *Session) authenticate(ctx context.Context, options gophercloud.AuthOptions) (*gophercloud.ProviderClient, error) {
	if client := s.cached(); client != nil {
		return client, nil
	}

	// The flight runs detached from the caller that happened to open it. A
	// cancelled context must not be inherited by the herd: an API handler whose
	// client has just hung up would otherwise become the leader, fail instantly,
	// and hand context.Canceled to every healthy reconcile that joined it — each
	// of which would have logged in perfectly well on its own. The login is
	// bounded by the client's own timeout instead, and a caller that gives up
	// leaves the login to finish and populate the cache rather than wasting it.
	detached := context.WithoutCancel(ctx)

	//nolint:nonamedreturns // the deferred recover below has to set the error.
	channel := s.login.DoChan("", func() (value any, err error) {
		// A panic must not escape the flight. singleflight cannot let one
		// propagate to a caller waiting on a channel, so it re-panics on a bare
		// goroutine and parks, deliberately unrecoverable — which would take the
		// process down. Callers here are controller-runtime reconciles and API
		// handlers, both of which recover a panic and fail one unit of work;
		// turning it into an error keeps that.
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("%w: panic during login: %v", coreerrors.ErrConsistency, recovered)
			}
		}()

		// A caller that joined a flight already in progress is served its
		// result, so anyone reaching here re-checks rather than logging in a
		// second time.
		if client := s.cached(); client != nil {
			return client, nil
		}

		// Built and bounded before authenticating, which is not
		// interchangeable with bounding it afterwards. gophercloud's v3auth
		// takes a throwaway copy of the client to reauthenticate with, and
		// ProviderClient.HTTPClient is a value field, so a copy made during the
		// login captures whatever timeout was set at that moment. Assigning
		// afterwards leaves the reauth client unbounded — and the reauth is the
		// one request every other caller on this credential waits behind.
		client, err := openstack.NewClient(options.IdentityEndpoint)
		if err != nil {
			return nil, err
		}

		client.HTTPClient.Timeout = providerRequestTimeout

		if err := openstack.Authenticate(detached, client, options); err != nil {
			return nil, err
		}

		s.lock.Lock()
		defer s.lock.Unlock()

		s.client = client

		return client, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case outcome := <-channel:
		if outcome.Err != nil {
			return nil, outcome.Err
		}

		client, ok := outcome.Val.(*gophercloud.ProviderClient)
		if !ok {
			return nil, fmt.Errorf("%w: login returned %T", coreerrors.ErrConsistency, outcome.Val)
		}

		return client, nil
	}
}

// sessions maps a credential to the state shared across every client built from
// it.
//
// Entries live for the life of the process and nothing evicts. They grow by two
// per OpenstackIdentity ever seen — the service principal's own password and the
// Region admin scoped to that identity's project — and an entry appears when a
// provider is constructed, whether or not it ever logs in. Rotating the Region
// admin secret re-keys every identity-scoped session, adding another entry per
// live identity. Each retains a decoded token response and the service catalog it
// closes over, which is tens of kilobytes rather than nothing. Worth bounding for
// a long-lived controller against a churning estate; the cost of an eviction is
// one login.
//
//nolint:gochecknoglobals
var sessions = &sessionRegistry{}

type sessionRegistry struct {
	lock     sync.Mutex
	sessions map[string]*Session
}

func (r *sessionRegistry) get(key string) *Session {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.sessions == nil {
		r.sessions = map[string]*Session{}
	}

	session, ok := r.sessions[key]
	if !ok {
		session = &Session{}
		r.sessions[key] = session
	}

	return session
}

// sessionFor returns the session shared by everything using this credential.
// The parts are the whole credential, so a rotated secret keys a new session and
// can never be served a client authenticated with the old one.
//
// What must really be keyed is everything that determines where the derived
// service clients point, which is the credential only because every New*Client
// passes a bare gophercloud.EndpointOpts{} and takes the first public catalog
// match. Should anything start selecting an endpoint by region, two OpenStack
// regions behind one Keystone reached with one admin credential would share a
// pinned catalog, and the region would have to join the key.
func sessionFor(parts ...string) *Session {
	hash := sha256.New()

	// Length-delimited so no two distinct tuples can hash alike.
	for _, part := range parts {
		_, _ = fmt.Fprintf(hash, "%d:%s", len(part), part)
	}

	return sessions.get(hex.EncodeToString(hash.Sum(nil)))
}
