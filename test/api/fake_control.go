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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
)

const fakeControlRequestTimeout = 30 * time.Second

// FakeControlEvent is one entry from a node's sidecar event log. The sidecar records
// one per driver operation, which is how a test proves the driver actually ran the op.
type FakeControlEvent struct {
	Seq     int    `json:"seq"`
	Op      string `json:"op"`
	Outcome string `json:"outcome"`
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
	endpoint   string
	token      string
	httpClient *http.Client
}

func NewFakeControlClient(config *TestConfig) *FakeControlClient {
	timeout := config.RequestTimeout
	if timeout == 0 {
		timeout = fakeControlRequestTimeout
	}

	return &FakeControlClient{
		endpoint:   strings.TrimSuffix(config.FakeControlEndpoint, "/"),
		token:      config.FakeNodeControlToken,
		httpClient: &http.Client{Timeout: timeout},
	}
}

func (c *FakeControlClient) nodePath(uuid string) string {
	return "/v1/nodes/" + url.PathEscape(uuid)
}

func (c *FakeControlClient) do(ctx context.Context, method, path string, body io.Reader, expectedStatus int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return nil, fmt.Errorf("creating fake-control request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing fake-control request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return respBody, fmt.Errorf("reading fake-control response: %w", err)
	}

	if expectedStatus != 0 && resp.StatusCode != expectedStatus {
		return respBody, fmt.Errorf("fake-control status %d, expected %d: %w", resp.StatusCode, expectedStatus, coreclient.ErrUnexpectedStatus)
	}

	return respBody, nil
}

// ProgramNodeBehavior sets how the node behaves on the next driver op, e.g.
// {"deploy": "fail"}. Register a ResetNode cleanup after calling.
func (c *FakeControlClient) ProgramNodeBehavior(ctx context.Context, uuid string, behavior map[string]any) {
	data, err := json.Marshal(behavior)
	Expect(err).NotTo(HaveOccurred(), "marshaling fake-control behavior")

	_, err = c.do(ctx, http.MethodPut, c.nodePath(uuid)+"/behavior", bytes.NewReader(data), http.StatusOK)
	Expect(err).NotTo(HaveOccurred(), "programming fake-control node behavior")
}

func (c *FakeControlClient) NodeEvents(ctx context.Context, uuid string) []FakeControlEvent {
	body, err := c.do(ctx, http.MethodGet, c.nodePath(uuid), nil, http.StatusOK)
	Expect(err).NotTo(HaveOccurred(), "reading fake-control node events")

	var state fakeControlNodeState

	Expect(json.Unmarshal(body, &state)).To(Succeed(), "decoding fake-control node state")

	return state.Events
}

// ResetNode clears the node's programmed behavior and event log. Mandatory in cleanup:
// the fixture node is shared, so a lingering fail program would poison a later run.
func (c *FakeControlClient) ResetNode(ctx context.Context, uuid string) {
	_, err := c.do(ctx, http.MethodDelete, c.nodePath(uuid), nil, http.StatusOK)
	Expect(err).NotTo(HaveOccurred(), "resetting fake-control node")
}
