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

//nolint:revive,testpackage // Ginkgo suite uses dot imports and package-local helper access.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeSidecar is an in-test stand-in for the ironic-fake-control loopback sidecar.
// It implements the subset of the /v1/nodes REST contract the client relies on so
// the client's request shaping and envelope decoding can be exercised hermetically.
type fakeSidecar struct {
	mu    sync.Mutex
	seq   int
	nodes map[string]*fakeControlNodeState
}

func newFakeSidecar() *fakeSidecar {
	return &fakeSidecar{nodes: map[string]*fakeControlNodeState{}}
}

func (s *fakeSidecar) node(uuid string) *fakeControlNodeState {
	if s.nodes[uuid] == nil {
		s.nodes[uuid] = &fakeControlNodeState{Behavior: map[string]any{}, Events: []FakeControlEvent{}}
	}

	return s.nodes[uuid]
}

//nolint:cyclop // dispatch mirrors the sidecar route table; splitting it obscures the contract
func (s *fakeSidecar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	switch {
	case r.Method == http.MethodPut && len(parts) == 4 && parts[3] == "behavior":
		var behavior map[string]any

		Expect(json.NewDecoder(r.Body).Decode(&behavior)).To(Succeed())
		s.node(parts[2]).Behavior = behavior
		writeJSON(w, map[string]string{"status": "ok"})
	case r.Method == http.MethodPost && len(parts) == 5 && parts[3] == "ops":
		node := s.node(parts[2])
		node.Events = append(node.Events, FakeControlEvent{Seq: s.seq, Op: parts[4], Outcome: "fail"})
		s.seq++

		writeJSON(w, map[string]string{"outcome": "fail"})
	case r.Method == http.MethodGet && len(parts) == 3:
		writeJSON(w, s.node(parts[2]))
	case r.Method == http.MethodDelete && len(parts) == 3:
		delete(s.nodes, parts[2])
		writeJSON(w, map[string]string{"status": "deleted"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	Expect(json.NewEncoder(w).Encode(v)).To(Succeed())
}

var _ = Describe("Fake control sidecar client", func() {
	Context("When deriving the node UUID from an infrastructure ref", func() {
		It("strips a scheme prefix and leaves a bare UUID untouched", func() {
			bare := "b3f1c0de-0000-4000-8000-000000000001"
			Expect(FakeControlNodeUUID(bare)).To(Equal(bare))
			Expect(FakeControlNodeUUID("openstack-ironic://" + bare)).To(Equal(bare))
			Expect(FakeControlNodeUUID("ironic://" + bare)).To(Equal(bare))
		})
	})

	Context("When talking to a running sidecar", Ordered, func() {
		var (
			server *httptest.Server
			client *FakeControlClient
			nodeID string
			reqCtx context.Context
		)

		BeforeAll(func() {
			server = httptest.NewServer(newFakeSidecar())
			DeferCleanup(server.Close)

			client = NewFakeControlClient(&TestConfig{
				FakeControlEndpoint: server.URL,
			})
			nodeID = "b3f1c0de-0000-4000-8000-000000000002"
			reqCtx = context.Background()
		})

		It("programs behavior, reads back recorded events, and resets the node", func() {
			client.ProgramNodeBehavior(reqCtx, nodeID, map[string]any{"deploy": "fail"})

			Expect(client.NodeEvents(reqCtx, nodeID)).To(BeEmpty())

			// Simulate the driver reporting two deploy ops against the node.
			postOp(server.URL, nodeID, "deploy")
			postOp(server.URL, nodeID, "deploy")

			events := client.NodeEvents(reqCtx, nodeID)
			Expect(events).To(HaveLen(2))

			var deployFailures int
			for _, event := range events {
				if event.Op == "deploy" && event.Outcome == "fail" {
					deployFailures++
				}
			}

			Expect(deployFailures).To(BeNumerically(">=", 2))

			client.ResetNode(reqCtx, nodeID)
			Expect(client.NodeEvents(reqCtx, nodeID)).To(BeEmpty())
		})
	})

	Context("When checking the configuration gate", func() {
		It("reports fake control unconfigured for an empty endpoint", func() {
			Expect(fakeControlConfigured(&TestConfig{})).To(BeFalse())
			Expect(fakeControlConfigured(&TestConfig{FakeControlEndpoint: "http://127.0.0.1:18080"})).To(BeTrue())
		})
	})
})

func postOp(baseURL, uuid, op string) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/v1/nodes/"+uuid+"/ops/"+op, strings.NewReader("{}"))
	Expect(err).NotTo(HaveOccurred())

	httpClient := &http.Client{Timeout: 5 * time.Second}

	resp, err := httpClient.Do(req)
	Expect(err).NotTo(HaveOccurred())

	defer resp.Body.Close()

	Expect(resp.StatusCode).To(Equal(http.StatusOK))
}
