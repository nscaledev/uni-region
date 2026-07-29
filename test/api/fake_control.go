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

//nolint:revive,staticcheck // dot imports are standard for Ginkgo/Gomega test code
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
)

const fakeControlRequestTimeout = 30 * time.Second

// Ops the fake-controllable driver consults the sidecar for. get_power is deliberately
// not wired (it is polled continuously, so a per-poll lock-held HTTP call is avoided) and
// no interface emits reboot, so neither can ever appear in an event log.
const (
	FakeControlOpDeploy        = "deploy"
	FakeControlOpPowerOn       = "power_on"
	FakeControlOpPowerOff      = "power_off"
	FakeControlOpSetBootDevice = "set_boot_device"
)

const (
	FakeControlOutcomeOK   = "ok"
	FakeControlOutcomeFail = "fail"
)

// FakeControlEvent is one entry from a node's sidecar event log. The sidecar records
// one per driver operation, which is how a test proves the driver actually ran the op.
type FakeControlEvent struct {
	Seq     int    `json:"seq"`
	Op      string `json:"op"`
	Outcome string `json:"outcome"`
}

// Behavior programs, in the sidecar's wire shape. These exist because the sidecar ignores
// keys it does not recognise and answers "ok": a misspelled or wrongly nested program
// injects no fault at all, so the suite silently exercises the happy path and fails much
// later as an unexplained status timeout. Building the shapes in one tested place keeps
// that failure mode out of the specs.
func FailDeploy() map[string]any {
	return map[string]any{"deploy": FakeControlOutcomeFail}
}

func FailPowerOn() map[string]any {
	return map[string]any{"power": map[string]any{"power_on": FakeControlOutcomeFail}}
}

func FailPowerOff() map[string]any {
	return map[string]any{"power": map[string]any{"power_off": FakeControlOutcomeFail}}
}

func FailSetBootDevice() map[string]any {
	return map[string]any{"management": map[string]any{"set_boot_device": FakeControlOutcomeFail}}
}

// CountEvents counts event-log entries for an op and outcome. Callers assert lower bounds
// on this, never exact counts: the driver can emit more than one call per provisioning
// attempt, and the region's retry cap is set out-of-process.
func CountEvents(events []FakeControlEvent, op, outcome string) int {
	count := 0

	for _, event := range events {
		if event.Op == op && event.Outcome == outcome {
			count++
		}
	}

	return count
}

// FakeControlNodeUUID normalises an infrastructure ref into the bare Ironic node UUID the
// sidecar keys on. Refs are bare UUIDs today, but a scheme-prefixed one would address a
// node the sidecar has never seen, and because its node store is create-on-write every
// request for that key still succeeds — injecting no fault and reporting no error.
func FakeControlNodeUUID(infrastructureRef string) string {
	for _, scheme := range []string{"openstack-ironic://", "ironic://"} {
		if rest, found := strings.CutPrefix(infrastructureRef, scheme); found {
			return rest
		}
	}

	return infrastructureRef
}

// fakeControlNodeState mirrors the sidecar's GET envelope for a node.
type fakeControlNodeState struct {
	Behavior map[string]any     `json:"behavior"`
	Events   []FakeControlEvent `json:"events"`
}

func fakeControlConfigured(config *TestConfig) bool {
	return config.FakeControlEndpoint != "" && config.FakeNodeControlToken != ""
}

// SkipUnlessFakeControlConfigured keeps the fault-injection suite strictly opt-in:
// neither the endpoint nor the token has a default.
func SkipUnlessFakeControlConfigured(config *TestConfig) {
	if !fakeControlConfigured(config) {
		Skip("fault-injection tests require FAKE_CONTROL_ENDPOINT and FAKE_NODE_CONTROL_TOKEN (ironic-fake-control sidecar)")
	}
}

// FakeControlClient talks to the ironic-fake-control sidecar. The sidecar is routable
// (tests run from CI runners, not the DevStack host) and rejects any request without
// the bearer token.
type FakeControlClient struct {
	client *coreclient.APIClient
}

func NewFakeControlClient(config *TestConfig) *FakeControlClient {
	timeout := config.RequestTimeout
	if timeout == 0 {
		timeout = fakeControlRequestTimeout
	}

	client := coreclient.NewAPIClient(config.FakeControlEndpoint, config.FakeNodeControlToken, timeout, &GinkgoLogger{})
	client.SetLogRequests(config.LogRequests)
	client.SetLogResponses(config.LogResponses)

	return &FakeControlClient{client: client}
}

func (c *FakeControlClient) nodePath(uuid string) string {
	return "/v1/nodes/" + url.PathEscape(uuid)
}

// ProgramNodeBehavior sets how the node behaves on the next driver op, e.g.
// {"deploy": "fail"}. Register a ResetNode cleanup after calling.
func (c *FakeControlClient) ProgramNodeBehavior(ctx context.Context, uuid string, behavior map[string]any) {
	data, err := json.Marshal(behavior)
	Expect(err).NotTo(HaveOccurred(), "marshaling fake-control behavior")

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, _, err = c.client.DoRequest(ctx, http.MethodPut, c.nodePath(uuid)+"/behavior", bytes.NewReader(data), http.StatusOK)
	Expect(err).NotTo(HaveOccurred(), "programming fake-control node behavior")
}

func (c *FakeControlClient) nodeState(ctx context.Context, uuid string) fakeControlNodeState {
	//nolint:bodyclose // DoRequest handles response body closing internally
	_, body, err := c.client.DoRequest(ctx, http.MethodGet, c.nodePath(uuid), nil, http.StatusOK)
	Expect(err).NotTo(HaveOccurred(), "reading fake-control node state")

	var state fakeControlNodeState

	Expect(json.Unmarshal(body, &state)).To(Succeed(), "decoding fake-control node state")

	return state
}

func (c *FakeControlClient) NodeEvents(ctx context.Context, uuid string) []FakeControlEvent {
	return c.nodeState(ctx, uuid).Events
}

// NodeBehavior reads back the node's programmed behavior. Tests use it to prove a node was
// left unprogrammed: the fixture node is shared, and a leftover fail program is the one
// failure that silently corrupts every later run rather than the run that caused it.
func (c *FakeControlClient) NodeBehavior(ctx context.Context, uuid string) map[string]any {
	return c.nodeState(ctx, uuid).Behavior
}

// ResetNode clears the node's programmed behavior and event log. Mandatory in cleanup:
// the fixture node is shared, so a lingering fail program would poison a later run.
func (c *FakeControlClient) ResetNode(ctx context.Context, uuid string) {
	//nolint:bodyclose // DoRequest handles response body closing internally
	_, _, err := c.client.DoRequest(ctx, http.MethodDelete, c.nodePath(uuid), nil, http.StatusOK)
	Expect(err).NotTo(HaveOccurred(), "resetting fake-control node")
}
