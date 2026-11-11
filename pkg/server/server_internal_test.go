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

package server

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/audit"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func auditOptions(t *testing.T, args ...string) *audit.Options {
	t.Helper()

	options := audit.NewOptions()

	flags := pflag.NewFlagSet("audit", pflag.ContinueOnError)
	options.AddFlags(flags)

	require.NoError(t, flags.Parse(args))

	return options
}

// With no collector configured the structured log is the only audit output,
// and no secrets are read, so an unconfigured install starts as before.
func TestNoCollectorMeansNoSink(t *testing.T) {
	t.Parallel()

	sinks, err := auditSinks(t.Context(), fake.NewClientBuilder().Build(), auditOptions(t))
	require.NoError(t, err)
	require.Empty(t, sinks)
}

// A configured collector whose credentials cannot be read stops the server at
// startup, rather than letting it run without delivering a record.
func TestUnreadableCollectorCredentialsFailStartup(t *testing.T) {
	t.Parallel()

	options := auditOptions(t,
		"--audit-host=https://audit.example.com",
		"--audit-ca-secret-namespace=audit",
		"--audit-ca-secret-name=missing",
		"--audit-client-certificate-namespace=audit",
		"--audit-client-certificate-name=missing",
		"--audit-signing-key-secret-namespace=audit",
		"--audit-signing-key-secret-name=missing",
	)

	_, err := auditSinks(t.Context(), fake.NewClientBuilder().Build(), options)
	require.Error(t, err)
}
