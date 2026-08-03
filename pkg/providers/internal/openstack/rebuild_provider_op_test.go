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
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/assert"
)

func TestRebuildProviderOp(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   *servers.Server
		want providerOp
	}{
		// Rebuild-admissible, so idle.
		{"active", &servers.Server{Status: novaStatusActive}, providerIdle},
		{"stopped", &servers.Server{Status: novaStatusShutoff}, providerIdle},

		// Errored, whatever the task says.
		{"errored", &servers.Server{Status: novaStatusError}, providerErrored},
		{"errored with a stuck task", &servers.Server{Status: novaStatusError, TaskState: "rebuilding"}, providerErrored},

		// A task in flight is busy regardless of the vm_state it accompanies.
		{"task in flight", &servers.Server{Status: novaStatusActive, TaskState: "rebuilding"}, providerBusy},

		// Stable and taskless, but Nova rejects a rebuild from all of these: busy
		// means "not actionable", which makes the pass wait rather than POST into a
		// 409 on every pass forever.
		{"awaiting resize confirmation", &servers.Server{Status: "VERIFY_RESIZE"}, providerBusy},
		{"paused", &servers.Server{Status: "PAUSED"}, providerBusy},
		{"suspended", &servers.Server{Status: "SUSPENDED"}, providerBusy},
		{"shelved offloaded", &servers.Server{Status: "SHELVED_OFFLOADED"}, providerBusy},
		{"rebuild status without a task", &servers.Server{Status: novaStatusRebuild}, providerBusy},
		{"building", &servers.Server{Status: novaStatusBuild}, providerBusy},
		{"unknown", &servers.Server{Status: novaStatusUnknown}, providerBusy},
		{"a status this version does not know", &servers.Server{Status: "MIGRATING"}, providerBusy},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, rebuildProviderOp(c.in))
		})
	}
}

func TestRebuildProviderImage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"absent", nil, ""},
		{"empty", map[string]any{"id": ""}, ""},
		{"not a string", map[string]any{"id": 42}, ""},
		{"unparseable", map[string]any{"id": "not-a-uuid"}, ""},
		{"readable", map[string]any{"id": imageIDStr("A")}, imageIDStr("A")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, c.want, rebuildProviderImage(&servers.Server{Image: c.in}))
		})
	}
}
