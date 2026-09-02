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
	"crypto/hmac"
	"crypto/rand"
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

// providerRequestTimeout bounds a single request made with a shared provider
// client, reauth included. It must be set: a zero-value http.Client has no
// timeout, and a shared client shares gophercloud's reauth serialisation, which
// waits without consulting a context. See the README's Credential Sessions
// section for what a caller can end up waiting for.
//
// A var, not a const, only so tests can shorten it.
//
//nolint:gochecknoglobals
var providerRequestTimeout = 60 * time.Second

// Session is the state shared by every service client built from one credential,
// and it outlives all of them: the authenticated ProviderClient, cached, and the
// single-flight that collapses concurrent cold-start logins.
//
// Caching the client has consequences that are not obvious from here -- the
// service catalog is pinned for the life of the process, and the reauth is not
// detached the way the cold-start login is. Both are written up in the README's
// Credential Sessions section, along with why this caches the ProviderClient
// rather than the derived service clients.
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
// DoChan and not Do: Do parks a follower on a WaitGroup it cannot interrupt, so
// a wedged login would hold every caller behind it. Here each caller stops
// waiting when its own context is done.
func (s *Session) authenticate(ctx context.Context, options gophercloud.AuthOptions) (*gophercloud.ProviderClient, error) {
	if client := s.cached(); client != nil {
		return client, nil
	}

	// Detached, so the caller that happens to open the flight cannot fail the
	// herd behind it: an API handler whose client has just hung up would
	// otherwise hand context.Canceled to every healthy reconcile that joined.
	// providerRequestTimeout is what bounds it instead.
	detached := context.WithoutCancel(ctx)

	//nolint:nonamedreturns // the deferred recover below has to set the error.
	channel := s.login.DoChan("", func() (value any, err error) {
		// singleflight re-panics on a bare goroutine when callers are waiting on
		// a channel, which is unrecoverable and would take the process down.
		// Reconciles and API handlers recover a panic and fail one unit of work;
		// keep that.
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("%w: panic during login: %v", coreerrors.ErrConsistency, recovered)
			}
		}()

		// Re-checked, because a herd straddling a completed flight reaches here
		// after the cache was filled.
		if client := s.cached(); client != nil {
			return client, nil
		}

		// Bounded BEFORE authenticating, and the two orders are not
		// interchangeable: v3auth takes a copy of the client to reauthenticate
		// with, and HTTPClient is a value field, so a timeout set afterwards never
		// reaches the reauth. Pinned by TestSessionBoundsTheLoginItself.
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
// it. Nothing evicts; the README's Credential Sessions section covers how it
// grows and why bounding it is worth doing.
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

// sessionKey is a process-lifetime random key, so the identifiers derived below
// are opaque outside this process and cannot be worked back to the credential
// they came from by anyone holding a digest.
//
//nolint:gochecknoglobals
var sessionKey = sync.OnceValue(func() []byte {
	key := make([]byte, sha256.Size)

	// A failure here means the platform has no entropy, which is not a condition
	// this process can sensibly continue under.
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("cannot generate a session key: %v", err))
	}

	return key
})

// sessionFor returns the session shared by everything using this credential.
// The parts are the whole credential, so a rotated secret keys a new session and
// can never be served a client authenticated with the old one.
//
// Keyed digest rather than the parts verbatim, because they include secrets and
// this is a map key that lives as long as the process. HMAC and not a bare hash:
// a credential's input space is small enough that an unkeyed digest is
// reversible by enumeration. This derives an identifier; it does not store or
// verify a password.
func sessionFor(parts ...string) *Session {
	digest := hmac.New(sha256.New, sessionKey())

	// Length-delimited so no two distinct tuples can collide.
	for _, part := range parts {
		_, _ = fmt.Fprintf(digest, "%d:%s", len(part), part)
	}

	return sessions.get(hex.EncodeToString(digest.Sum(nil)))
}
