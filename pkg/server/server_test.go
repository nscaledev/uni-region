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
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	openapimiddlewareremote "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/region/pkg/server"
)

// TestAddFlagsRegistersAuthorizationEngineDefaults guards the "off" default:
// the remote-authorization seam must stay inert (today's local ACL walk)
// until an operator explicitly opts a deployment into shadow/enforce, and
// the 250ms check-timeout default must match the engine's own built-in
// default so an unconfigured deployment behaves identically to one that
// never wired the flag at all.
func TestAddFlagsRegistersAuthorizationEngineDefaults(t *testing.T) {
	t.Parallel()

	s := &server.Server{}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	s.AddFlags(flags)

	modeFlag := flags.Lookup("authorization-engine-mode")
	require.NotNil(t, modeFlag, "authorization-engine-mode flag must be registered")
	require.Equal(t, "off", modeFlag.DefValue)
	require.Equal(t, "off", s.AuthorizationEngineMode)

	timeoutFlag := flags.Lookup("authorization-check-timeout")
	require.NotNil(t, timeoutFlag, "authorization-check-timeout flag must be registered")
	require.Equal(t, "250ms", timeoutFlag.DefValue)
	require.Equal(t, 250*time.Millisecond, s.AuthorizationCheckTimeout)
}

// TestRemoteAuthorizerOptionsParsesValidModes proves each whitelisted mode
// string actually reaches the constructed Authorizer as the corresponding
// rbac.RemoteMode, by applying the returned options to a real Authorizer and
// reading the mode back -- not just that ParseRemoteMode returns no error.
func TestRemoteAuthorizerOptionsParsesValidModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode     string
		wantMode rbac.RemoteMode
	}{
		{mode: "off", wantMode: rbac.RemoteOff},
		{mode: "shadow", wantMode: rbac.RemoteShadow},
		{mode: "enforce", wantMode: rbac.RemoteEnforce},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			t.Parallel()

			s := &server.Server{AuthorizationEngineMode: tt.mode, AuthorizationCheckTimeout: 250 * time.Millisecond}

			opts, err := s.RemoteAuthorizerOptions()
			require.NoError(t, err)
			require.Len(t, opts, 2, "a positive AuthorizationCheckTimeout must append a WithCheckTimeout option")

			a := &openapimiddlewareremote.Authorizer{}
			for _, opt := range opts {
				opt(a)
			}

			require.Equal(t, tt.wantMode, a.RemoteEngineMode())
		})
	}
}

// TestRemoteAuthorizerOptionsRejectsInvalidMode ensures a typo'd or otherwise
// unrecognized mode string surfaces as an error instead of silently falling
// back to RemoteOff -- a misconfigured deployment must fail to start, not
// silently serve today's behavior while believing it is shadowing or
// enforcing the remote PDP.
func TestRemoteAuthorizerOptionsRejectsInvalidMode(t *testing.T) {
	t.Parallel()

	s := &server.Server{AuthorizationEngineMode: "bogus"}

	opts, err := s.RemoteAuthorizerOptions()
	require.ErrorIs(t, err, rbac.ErrInvalidRemoteMode)
	require.Nil(t, opts)
}

// TestRemoteAuthorizerOptionsOmitsTimeoutOverrideWhenNonPositive guards the
// zero-value footgun called out in the wiring: WithCheckTimeout(0) disables
// CheckMany's deadline entirely, so a non-positive AuthorizationCheckTimeout
// (the Server zero-value, or an explicit 0/negative override) must never
// reach it -- leaving the engine's own 250ms default in force.
func TestRemoteAuthorizerOptionsOmitsTimeoutOverrideWhenNonPositive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{name: "zero value", timeout: 0},
		{name: "negative", timeout: -time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &server.Server{AuthorizationEngineMode: "off", AuthorizationCheckTimeout: tt.timeout}

			opts, err := s.RemoteAuthorizerOptions()
			require.NoError(t, err)
			require.Len(t, opts, 1, "a non-positive timeout must not append a WithCheckTimeout option")
		})
	}
}
