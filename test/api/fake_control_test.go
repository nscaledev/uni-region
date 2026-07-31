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

const (
	fakeSidecarToken  = "test-sidecar-token"
	fakeSidecarNodeID = "b3f1c0de-0000-4000-8000-000000000002"
)

// decideFakeSidecarOutcome ports the sidecar's decision logic. It is a port rather than a
// stub on purpose: a double that answers "fail" unconditionally makes every assertion about
// programmed behavior vacuous, because it passes just as well with no program at all.
//
// delay_s is not modelled — the driver sleeps on it, the client never observes it.
func decideFakeSidecarOutcome(behavior map[string]any, op string) string {
	if len(behavior) == 0 || op == "get_power" {
		return FakeControlOutcomeOK
	}

	if op == FakeControlOpDeploy {
		switch program := behavior[FakeControlOpDeploy].(type) {
		case string:
			if program == FakeControlOutcomeFail {
				return FakeControlOutcomeFail
			}
		case map[string]any:
			if program[FakeControlOpDeploy] == FakeControlOutcomeFail {
				return FakeControlOutcomeFail
			}
		}

		return FakeControlOutcomeOK
	}

	// Mirrors the sidecar's _OP_MAP: which behavior section and key each op reads. deploy
	// is absent because it is read from the top level, not from a section.
	opSections := map[string][2]string{
		FakeControlOpPowerOn:       {"power", "power_on"},
		FakeControlOpPowerOff:      {"power", "power_off"},
		FakeControlOpSetBootDevice: {"management", "set_boot_device"},
	}

	mapping, wired := opSections[op]
	if !wired {
		return FakeControlOutcomeOK
	}

	section, _ := behavior[mapping[0]].(map[string]any)
	if section[mapping[1]] == FakeControlOutcomeFail {
		return FakeControlOutcomeFail
	}

	return FakeControlOutcomeOK
}

// fakeSidecar implements the subset of the sidecar's /v1/nodes contract the client relies
// on, including its bearer-token check and its create-on-write node store, so request
// shaping and envelope decoding can be exercised hermetically.
type fakeSidecar struct {
	mu    sync.Mutex
	seq   int
	nodes map[string]*fakeControlNodeState
}

func newFakeSidecar() *fakeSidecar {
	return &fakeSidecar{nodes: map[string]*fakeControlNodeState{}}
}

// node mirrors the real store's setdefault: addressing an unknown node creates it rather
// than reporting an error.
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

	if r.Header.Get("Authorization") != "Bearer "+fakeSidecarToken {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	switch {
	case r.Method == http.MethodPut && len(parts) == 4 && parts[3] == "behavior":
		var behavior map[string]any

		if err := json.NewDecoder(r.Body).Decode(&behavior); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		s.node(parts[2]).Behavior = behavior
		writeJSON(w, map[string]string{"status": "ok"})
	case r.Method == http.MethodPost && len(parts) == 5 && parts[3] == "ops":
		node := s.node(parts[2])
		op := parts[4]
		outcome := decideFakeSidecarOutcome(node.Behavior, op)
		node.Events = append(node.Events, FakeControlEvent{Seq: s.seq, Op: op, Outcome: outcome})
		s.seq++

		writeJSON(w, map[string]any{"outcome": outcome, "delay_s": 0, "error": nil})
	case r.Method == http.MethodGet && len(parts) == 3:
		writeJSON(w, s.node(parts[2]))
	case r.Method == http.MethodDelete && len(parts) == 3:
		delete(s.nodes, parts[2])
		writeJSON(w, map[string]string{"status": "deleted"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// writeJSON avoids Gomega assertions: this runs on the server's goroutine, where a failure
// would panic instead of reporting against the spec.
func writeJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// postOp drives an op against the fixture node the way the driver does, and returns the
// outcome the sidecar decided.
func postOp(baseURL, op string) string {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/v1/nodes/"+fakeSidecarNodeID+"/ops/"+op, strings.NewReader("{}"))
	Expect(err).NotTo(HaveOccurred())

	req.Header.Set("Authorization", "Bearer "+fakeSidecarToken)

	httpClient := &http.Client{Timeout: 5 * time.Second}

	resp, err := httpClient.Do(req)
	Expect(err).NotTo(HaveOccurred())

	defer resp.Body.Close()

	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	var decoded struct {
		Outcome string `json:"outcome"`
	}

	Expect(json.NewDecoder(resp.Body).Decode(&decoded)).To(Succeed())

	return decoded.Outcome
}

var _ = Describe("Fake control sidecar client", func() {
	var (
		sidecarURL string
		client     *FakeControlClient
		reqCtx     context.Context
	)

	BeforeEach(func() {
		server := httptest.NewServer(newFakeSidecar())
		DeferCleanup(server.Close)

		sidecarURL = server.URL
		client = NewFakeControlClient(&TestConfig{
			FakeControlEndpoint:  server.URL,
			FakeNodeControlToken: fakeSidecarToken,
		})
		reqCtx = context.Background()
	})

	Context("When programming node behavior", func() {
		Describe("Given a deploy fail program", func() {
			It("sends the wire shape the sidecar reads, and deploy then fails", func() {
				client.ProgramNodeBehavior(reqCtx, fakeSidecarNodeID, FailDeploy())

				Expect(client.NodeBehavior(reqCtx, fakeSidecarNodeID)).
					To(Equal(map[string]any{"deploy": "fail"}),
						"deploy program must match the shape the sidecar's decision logic reads")
				Expect(postOp(sidecarURL, FakeControlOpDeploy)).To(Equal(FakeControlOutcomeFail),
					"deploy must actually fail once programmed")
			})
		})

		Describe("Given a program targeting a single op", func() {
			It("fails only that op and leaves the others healthy", func() {
				client.ProgramNodeBehavior(reqCtx, fakeSidecarNodeID, FailDeploy())

				Expect(postOp(sidecarURL, FakeControlOpDeploy)).To(Equal(FakeControlOutcomeFail))
				Expect(postOp(sidecarURL, FakeControlOpPowerOn)).To(Equal(FakeControlOutcomeOK))
				Expect(postOp(sidecarURL, FakeControlOpSetBootDevice)).To(Equal(FakeControlOutcomeOK))
			})
		})

		Describe("Given no program at all", func() {
			It("reports every controllable op healthy", func() {
				for _, op := range []string{
					FakeControlOpDeploy,
					FakeControlOpPowerOn,
					FakeControlOpPowerOff,
					FakeControlOpSetBootDevice,
				} {
					Expect(postOp(sidecarURL, op)).To(Equal(FakeControlOutcomeOK),
						"%s must succeed on an unprogrammed node", op)
				}
			})
		})
	})

	Context("When reading the event log", func() {
		Describe("Given the node has run ops under a fail program", func() {
			It("records every op with the outcome the sidecar decided", func() {
				client.ProgramNodeBehavior(reqCtx, fakeSidecarNodeID, FailDeploy())

				Expect(client.NodeEvents(reqCtx, fakeSidecarNodeID)).To(BeEmpty(),
					"programming alone must not record events")

				postOp(sidecarURL, FakeControlOpPowerOn)
				postOp(sidecarURL, FakeControlOpDeploy)
				postOp(sidecarURL, FakeControlOpDeploy)

				events := client.NodeEvents(reqCtx, fakeSidecarNodeID)
				Expect(events).To(HaveLen(3))
				Expect(events[0].Op).To(Equal(FakeControlOpPowerOn))
				Expect(events[0].Outcome).To(Equal(FakeControlOutcomeOK))
				Expect(events[1].Outcome).To(Equal(FakeControlOutcomeFail))
				Expect(events[2].Outcome).To(Equal(FakeControlOutcomeFail))
			})
		})

		Describe("Given a mix of ops and outcomes", func() {
			It("counts only the requested op and outcome pair", func() {
				events := []FakeControlEvent{
					{Seq: 0, Op: FakeControlOpPowerOn, Outcome: FakeControlOutcomeOK},
					{Seq: 1, Op: FakeControlOpDeploy, Outcome: FakeControlOutcomeFail},
					{Seq: 2, Op: FakeControlOpDeploy, Outcome: FakeControlOutcomeOK},
					{Seq: 3, Op: FakeControlOpDeploy, Outcome: FakeControlOutcomeFail},
					{Seq: 4, Op: FakeControlOpPowerOff, Outcome: FakeControlOutcomeFail},
				}

				Expect(CountEvents(events, FakeControlOpDeploy, FakeControlOutcomeFail)).To(Equal(2))
				Expect(CountEvents(events, FakeControlOpDeploy, FakeControlOutcomeOK)).To(Equal(1))
				Expect(CountEvents(events, FakeControlOpPowerOff, FakeControlOutcomeFail)).To(Equal(1))
				Expect(CountEvents(events, FakeControlOpSetBootDevice, FakeControlOutcomeFail)).To(BeZero())
				Expect(CountEvents(nil, FakeControlOpDeploy, FakeControlOutcomeFail)).To(BeZero())
			})
		})
	})

	Context("When resetting a node", func() {
		Describe("Given the node carries a fail program and recorded events", func() {
			It("clears both, so a shared fixture node cannot poison a later run", func() {
				client.ProgramNodeBehavior(reqCtx, fakeSidecarNodeID, FailDeploy())
				postOp(sidecarURL, FakeControlOpDeploy)

				client.ResetNode(reqCtx, fakeSidecarNodeID)

				Expect(client.NodeBehavior(reqCtx, fakeSidecarNodeID)).To(BeEmpty(),
					"a surviving fail program would silently fail the next run instead of this one")
				Expect(client.NodeEvents(reqCtx, fakeSidecarNodeID)).To(BeEmpty())
				Expect(postOp(sidecarURL, FakeControlOpDeploy)).To(Equal(FakeControlOutcomeOK))
			})
		})

		Describe("Given a node the sidecar has never seen", func() {
			It("succeeds, so cleanup can run before any state exists", func() {
				client.ResetNode(reqCtx, "6f3d9b71-0000-4000-8000-00000000dead")
			})
		})
	})

	Context("When addressing a node the sidecar has never seen", func() {
		It("reports empty state rather than an error", func() {
			// Pins the wrong-UUID hazard: the node store is create-on-write, so a
			// mistyped or scheme-prefixed ref is accepted by every endpoint, injects
			// no fault, and reports no error. The live suite defends against this by
			// asserting the driver actually recorded events for the UUID it programmed.
			Expect(client.NodeEvents(reqCtx, "6f3d9b71-0000-4000-8000-00000000beef")).To(BeEmpty())
			Expect(client.NodeBehavior(reqCtx, "6f3d9b71-0000-4000-8000-00000000beef")).To(BeEmpty())
		})
	})

	Context("When normalising an infrastructure ref", func() {
		It("strips a provider scheme down to the bare node UUID", func() {
			Expect(FakeControlNodeUUID(fakeSidecarNodeID)).To(Equal(fakeSidecarNodeID))
			Expect(FakeControlNodeUUID("ironic://" + fakeSidecarNodeID)).To(Equal(fakeSidecarNodeID))
			Expect(FakeControlNodeUUID("openstack-ironic://" + fakeSidecarNodeID)).To(Equal(fakeSidecarNodeID))
			Expect(FakeControlNodeUUID("")).To(BeEmpty())
		})
	})

	Context("When checking the configuration gate", func() {
		It("reports fake control configured only when both endpoint and token are set", func() {
			Expect(fakeControlConfigured(&TestConfig{})).To(BeFalse())
			Expect(fakeControlConfigured(&TestConfig{FakeControlEndpoint: "http://sidecar.example:18080"})).To(BeFalse())
			Expect(fakeControlConfigured(&TestConfig{FakeNodeControlToken: fakeSidecarToken})).To(BeFalse())
			Expect(fakeControlConfigured(&TestConfig{
				FakeControlEndpoint:  "http://sidecar.example:18080",
				FakeNodeControlToken: fakeSidecarToken,
			})).To(BeTrue())
		})
	})
})
