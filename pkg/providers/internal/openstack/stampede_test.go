//go:build stampede

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

// This file is a load harness, not a test. It replays the shape of a
// controller-restart resync against a crude queueing model of Keystone and
// Nova, so the cost of a change to the provider client layer can be measured
// rather than argued about. It asserts nothing and is behind a build tag.
//
//	go test -tags stampede -timeout 40m -count 1 -v \
//	    -run TestStampede ./pkg/providers/internal/openstack/
//
// Two runs:
//
//   - TestStampedeIncident replays the 26 Aug population: 1157 servers pinned
//     to one identity, 34 pinned to a second, 347 spread over 17 tenant
//     identities, across two clouds of identical capacity. Identical capacity is
//     deliberate: any difference in outcome between cohorts then comes from the
//     population shape alone, not from one cloud being busier.
//   - TestStampedeScaling sweeps servers-in-one-project, which is the population
//     the cost scales with, and reports where the resync stops completing.
//
// The service-time constants are FITTED to be plausible, not measured from any
// real cloud. Absolute numbers are illustrative; the before/after ratio and the
// shape of the scaling curve are the result.
package openstack_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	idstest "github.com/unikorn-cloud/region/pkg/ids/idstest"
	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Model parameters
// ---------------------------------------------------------------------------

const (
	// The per-unit costs below are chosen to be defensible orders of magnitude
	// for the work each unit actually does, NOT fitted to reproduce any
	// particular incident wall clock. An earlier version of this harness was
	// fitted, and needed a per-row cost two orders of magnitude beyond anything
	// a database does to make the numbers land — which is itself a result: the
	// read pattern cannot account for a multi-minute resync on its own.

	// keystoneWorkers is how many password grants the identity service will
	// process at once. A grant is dominated by the key derivation function, so
	// this is a CPU-bound pool.
	keystoneWorkers = 8
	// keystoneGrantCost is one password grant plus catalog build. The KDF
	// dominates and is deliberately expensive.
	keystoneGrantCost = 150 * time.Millisecond

	// novaWorkers is how many API requests the compute service will process at
	// once, per cloud.
	novaWorkers = 8
	// novaRequestCost is the fixed cost of any request: token validation, policy
	// evaluation, a database connection, response framing.
	novaRequestCost = 15 * time.Millisecond
	// novaScanCostPlain is the cost of reading one instance row of the project.
	novaScanCostPlain = 2 * time.Microsecond
	// novaScanCostRegex is the same read plus evaluating a regular expression
	// against the row's display_name, which is what a name filter costs. Three
	// times the plain read, not a hundred times: a regular expression match on a
	// short string is not free but it is not the dominant term either.
	novaScanCostRegex = 6 * time.Microsecond
	// novaEmitCost is the cost of one instance row that is actually RETURNED:
	// building the detail record (its flavor, image, addresses and security
	// groups), serialising it, putting it on the wire, and decoding it client
	// side. This is the term the earlier fitted model omitted entirely, and it is
	// the one that punishes an unfiltered read: a filtered list returns one row,
	// an unfiltered list returns every row in the project.
	novaEmitCost = 40 * time.Microsecond

	// novaMaxLimit is Nova's [api] max_limit: the most instances one page of a
	// list response can carry. An unfiltered read of a larger project is several
	// round trips, each paying the fixed request cost again.
	novaMaxLimit = 1000

	// queueDepth is how many requests the front end holds before shedding a 503.
	queueDepth = 512
	// queueWait is how long a queued request waits for a worker before the front
	// end gives up with a 504.
	queueWait = 8 * time.Second

	// reconcileDeadline is the per-reconcile context budget.
	reconcileDeadline = 10 * time.Second

	// maxConcurrency models --max-concurrency, which defaults to the host's core
	// count rather than the container's CPU limit.
	maxConcurrency = 64

	// pollPeriod is the monitor's --poll-period default. A monitor cycle that
	// takes longer than this can never keep up.
	pollPeriod = time.Minute
)

// ---------------------------------------------------------------------------
// Queueing model
// ---------------------------------------------------------------------------

// serviceModel is a bounded worker pool behind a bounded queue: the shape every
// OpenStack API service has. Requests past the backlog are shed with a 503;
// requests that wait too long for a worker get a 504.
type serviceModel struct {
	name    string
	workers chan struct{}

	queued    atomic.Int64
	peakQueue atomic.Int64

	served   atomic.Int64
	shed     atomic.Int64
	expired  atomic.Int64
	rows     atomic.Int64
	emitted  atomic.Int64
	busyTime atomic.Int64
}

func newServiceModel(name string, workers int) *serviceModel {
	return &serviceModel{
		name:    name,
		workers: make(chan struct{}, workers),
	}
}

// enter queues for a worker, reporting whether the caller may proceed. It writes
// the failure response itself.
func (s *serviceModel) enter(w http.ResponseWriter) bool {
	depth := s.queued.Add(1)
	defer s.queued.Add(-1)

	for {
		peak := s.peakQueue.Load()
		if depth <= peak || s.peakQueue.CompareAndSwap(peak, depth) {
			break
		}
	}

	if depth > queueDepth {
		s.shed.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)

		return false
	}

	timer := time.NewTimer(queueWait)
	defer timer.Stop()

	select {
	case s.workers <- struct{}{}:
		return true
	case <-timer.C:
		s.expired.Add(1)
		w.WriteHeader(http.StatusGatewayTimeout)

		return false
	}
}

// work holds a worker for the modelled service time, then releases it.
func (s *serviceModel) work(cost time.Duration) {
	time.Sleep(cost)
	s.served.Add(1)
	s.busyTime.Add(int64(cost))
	<-s.workers
}

// ---------------------------------------------------------------------------
// Fake cloud
// ---------------------------------------------------------------------------

// cloud is one modelled OpenStack region: an identity service, a compute
// service, and a record of how many instances each project holds.
type cloud struct {
	name     string
	keystone *serviceModel
	nova     *serviceModel

	// lock guards projects, which a create burst mutates.
	lock     sync.RWMutex
	projects map[string][]string

	identityURL string
	computeURL  string

	server *httptest.Server
}

func newCloud(name string, projectSize map[string]int) *cloud {
	c := &cloud{
		name:     name,
		keystone: newServiceModel(name+"/keystone", keystoneWorkers),
		nova:     newServiceModel(name+"/nova", novaWorkers),
		projects: map[string][]string{},
	}

	for project, size := range projectSize {
		names := make([]string, 0, size)

		for i := range size {
			names = append(names, stampedeServerName(project, i))
		}

		c.projects[project] = names
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v3/auth/tokens", c.token)
	mux.HandleFunc("/compute/", c.compute)

	c.server = httptest.NewServer(mux)
	c.identityURL = c.server.URL + "/v3/"
	c.computeURL = c.server.URL + "/compute"

	return c
}

func (c *cloud) Close() {
	c.server.Close()
}

// token is the identity service. The catalog it returns points the caller at a
// project-scoped compute endpoint, which is how the compute side knows which
// project a request belongs to without a real token store.
func (c *cloud) token(w http.ResponseWriter, r *http.Request) {
	if !c.keystone.enter(w) {
		return
	}

	var body struct {
		Auth struct {
			Scope struct {
				Project struct {
					ID string `json:"id"`
				} `json:"project"`
			} `json:"scope"`
		} `json:"auth"`
	}

	_ = json.NewDecoder(r.Body).Decode(&body)

	project := body.Auth.Scope.Project.ID
	if project == "" {
		project = "unscoped"
	}

	c.keystone.work(keystoneGrantCost)

	// Versioned catalog URLs, as a real cloud publishes them: gophercloud reads
	// the version out of the URL and skips the endpoint discovery GET it would
	// otherwise make on every client construction.
	compute := fmt.Sprintf("%s/p/%s/v2.1", c.computeURL, project)
	network := fmt.Sprintf("%s/p/%s/v2.0", c.computeURL, project)

	response := map[string]any{
		"token": map[string]any{
			"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"catalog": []map[string]any{
				{
					"id":   "compute",
					"name": "nova",
					"type": "compute",
					"endpoints": []map[string]any{
						{"id": "c1", "interface": "public", "region": "", "url": compute},
					},
				},
				{
					"id":   "network",
					"name": "neutron",
					"type": "network",
					"endpoints": []map[string]any{
						{"id": "n1", "interface": "public", "region": "", "url": network},
					},
				},
			},
		},
	}

	w.Header().Set("X-Subject-Token", "modelled-token")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// compute serves the project-scoped compute endpoint: a paginated, optionally
// name-filtered detail list, and a create.
func (c *cloud) compute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/compute/p/")

	project, rest, ok := strings.Cut(path, "/")
	if !ok {
		http.NotFound(w, r)

		return
	}

	switch {
	case r.Method == http.MethodGet && rest == "v2.1/servers/detail":
		c.listServers(w, r, project)
	case r.Method == http.MethodPost && rest == "v2.1/servers":
		c.createServer(w, project)
	default:
		http.NotFound(w, r)
	}
}

// listServers charges for the instance rows the query has to touch, and for the
// rows it actually returns, then honours Nova's page limit.
func (c *cloud) listServers(w http.ResponseWriter, r *http.Request, project string) {
	if !c.nova.enter(w) {
		return
	}

	names := c.projectServers(project)

	filter := r.URL.Query().Get("name")
	marker := r.URL.Query().Get("marker")

	// Both forms read every row of the project; only the filtered one pays a
	// regular expression per row. But only the rows actually RETURNED are built,
	// serialised, put on the wire and decoded — one row against the whole
	// project, which is where the two forms really differ.
	scanCost := novaScanCostPlain
	if filter != "" {
		scanCost = novaScanCostRegex
	}

	selected := make([]string, 0, len(names))
	past := marker == ""

	for _, name := range names {
		if !past {
			if name == marker {
				past = true
			}

			continue
		}

		if filter == "" || strings.HasPrefix(name, filter) {
			selected = append(selected, name)
		}
	}

	truncated := len(selected) > novaMaxLimit
	if truncated {
		selected = selected[:novaMaxLimit]
	}

	c.nova.rows.Add(int64(len(names)))
	c.nova.emitted.Add(int64(len(selected)))
	c.nova.work(novaRequestCost +
		time.Duration(len(names))*scanCost +
		time.Duration(len(selected))*novaEmitCost)

	var out strings.Builder

	out.WriteString(`{"servers":[`)

	for i, name := range selected {
		if i > 0 {
			out.WriteString(",")
		}

		fmt.Fprintf(&out, `{"id":"%s","name":%q,"status":"ACTIVE"}`, name, name)
	}

	out.WriteString(`]`)

	// Nova advertises a next page by marker when it truncates.
	if truncated {
		next := fmt.Sprintf("%s/p/%s/v2.1/servers/detail?marker=%s",
			c.computeURL, project, selected[len(selected)-1])
		if filter != "" {
			next += "&name=" + filter
		}

		fmt.Fprintf(&out, `,"servers_links":[{"rel":"next","href":%q}]`, next)
	}

	out.WriteString(`}`)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(out.String()))
}

// createServer adds an instance to the project, so a create burst grows the
// thing every subsequent read has to walk.
func (c *cloud) createServer(w http.ResponseWriter, project string) {
	if !c.nova.enter(w) {
		return
	}

	c.nova.work(novaRequestCost)

	c.lock.Lock()
	name := stampedeServerName(project, len(c.projects[project]))
	c.projects[project] = append(c.projects[project], name)
	c.lock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, `{"server":{"id":"%s","name":%q,"status":"BUILD"}}`, name, name)
}

func (c *cloud) projectServers(project string) []string {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return slices.Clone(c.projects[project])
}

func stampedeServerName(project string, index int) string {
	return fmt.Sprintf("%s-server-%d", project, index)
}

// ---------------------------------------------------------------------------
// Workload
// ---------------------------------------------------------------------------

// cohort is a group of servers sharing one credential.
type cohort struct {
	label   string
	cloud   *cloud
	project string
	userID  string
	servers int
}

type outcome struct {
	label   string
	ok      bool
	class   string
	latency time.Duration
}

// reconcile is one server's worth of provider work on the resync path: the two
// client constructions a reconcile performs (network and compute, each a full
// AuthenticatedClient today) followed by the GetServer read.
func reconcile(ctx context.Context, c cohort, index int) outcome {
	start := time.Now()

	result := func(class string, ok bool) outcome {
		return outcome{label: c.label, ok: ok, class: class, latency: time.Since(start)}
	}

	credential := openstack.NewPasswordProvider(c.cloud.identityURL, c.userID, "password", c.project)

	if _, err := openstack.NewNetworkClient(ctx, credential, nil); err != nil {
		return result(classify("network-client", err), false)
	}

	compute, err := openstack.NewComputeClient(ctx, credential, nil)
	if err != nil {
		return result(classify("compute-client", err), false)
	}

	server := stampedeServerFixture(c.project, index)

	_, err = compute.GetServer(ctx, server)

	switch {
	case err == nil:
		return result("ok", true)
	case !errors.Is(err, coreerrors.ErrResourceNotFound):
		return result(classify("get-server", err), false)
	}

	// Confirmed absent, so this is the create path: exactly what reconcileServer
	// does, and the reason the read cannot be served from before a create.
	if _, err := compute.CreateServer(ctx, server, "", nil, nil, nil); err != nil {
		return result(classify("create-server", err), false)
	}

	return result("created", true)
}

func classify(stage string, err error) string {
	message := err.Error()

	switch {
	case strings.Contains(message, "context deadline exceeded"):
		return stage + "/deadline"
	case strings.Contains(message, "503"):
		return stage + "/shed-503"
	case strings.Contains(message, "504"):
		return stage + "/timeout-504"
	case strings.Contains(message, "resource not found"):
		return stage + "/not-found"
	default:
		return stage + "/other: " + truncate(message, 120)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n]
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

type runResult struct {
	elapsed time.Duration
	total   int
	results []outcome
	clouds  []*cloud
}

func run(cohorts []cohort, clouds []*cloud) runResult {
	total := 0
	for _, c := range cohorts {
		total += c.servers
	}

	results := make([]outcome, 0, total)

	var (
		mutex sync.Mutex
		group sync.WaitGroup
	)

	gate := make(chan struct{}, maxConcurrency)

	start := time.Now()

	for _, c := range cohorts {
		for index := range c.servers {
			group.Add(1)

			go func(c cohort, index int) {
				defer group.Done()

				gate <- struct{}{}
				defer func() { <-gate }()

				ctx, cancel := context.WithTimeout(context.Background(), reconcileDeadline)
				defer cancel()

				result := reconcile(ctx, c, index)

				mutex.Lock()
				results = append(results, result)
				mutex.Unlock()
			}(c, index)
		}
	}

	group.Wait()

	return runResult{elapsed: time.Since(start), total: total, results: results, clouds: clouds}
}

func (r runResult) failed() int {
	failed := 0

	for _, o := range r.results {
		if !o.ok {
			failed++
		}
	}

	return failed
}

func (r runResult) percentile(p float64) time.Duration {
	latencies := make([]time.Duration, 0, len(r.results))
	for _, o := range r.results {
		latencies = append(latencies, o.latency)
	}

	if len(latencies) == 0 {
		return 0
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	return latencies[int(p*float64(len(latencies)-1))].Round(time.Millisecond)
}

func (r runResult) rows() int64 {
	var rows int64

	for _, c := range r.clouds {
		rows += c.nova.rows.Load()
	}

	return rows
}

func (r runResult) emitted() int64 {
	var emitted int64

	for _, c := range r.clouds {
		emitted += c.nova.emitted.Load()
	}

	return emitted
}

func (r runResult) logins() int64 {
	var logins int64

	for _, c := range r.clouds {
		logins += c.keystone.served.Load() + c.keystone.shed.Load() + c.keystone.expired.Load()
	}

	return logins
}

func (r runResult) novaCalls() int64 {
	var calls int64

	for _, c := range r.clouds {
		calls += c.nova.served.Load() + c.nova.shed.Load() + c.nova.expired.Load()
	}

	return calls
}

// ---------------------------------------------------------------------------
// Incident replay
// ---------------------------------------------------------------------------

// incidentWorkload builds the 26 Aug population: 1157 servers pinned to one
// identity, 34 pinned to a second in another cloud, and 347 spread over 17
// tenant identities across both. Both clouds get identical capacity, so any
// difference between cohorts comes from the population shape rather than from
// one cloud being busier than the other.
func incidentWorkload() ([]*cloud, []cohort) {
	type spec struct {
		label   string
		project string
		userID  string
		servers int
		second  bool
	}

	specs := []spec{
		{label: "pinned/1157", project: "project-a", userID: "region-admin", servers: 1157},
		{label: "pinned/34", project: "project-b", userID: "region-admin", servers: 34, second: true},
	}

	remaining := 347

	for i := range 17 {
		size := remaining / (17 - i)
		remaining -= size

		specs = append(specs, spec{
			label:   "unpinned",
			project: fmt.Sprintf("project-t%d", i),
			userID:  fmt.Sprintf("sp-t%d", i),
			servers: size,
			second:  i%2 == 1,
		})
	}

	sizeA := map[string]int{}
	sizeB := map[string]int{}

	for _, s := range specs {
		if s.second {
			sizeB[s.project] = s.servers
		} else {
			sizeA[s.project] = s.servers
		}
	}

	cloudA := newCloud("region-a", sizeA)
	cloudB := newCloud("region-b", sizeB)

	cohorts := make([]cohort, 0, len(specs))

	for _, s := range specs {
		target := cloudA
		if s.second {
			target = cloudB
		}

		cohorts = append(cohorts, cohort{
			label:   s.label,
			cloud:   target,
			project: s.project,
			userID:  s.userID,
			servers: s.servers,
		})
	}

	return []*cloud{cloudA, cloudB}, cohorts
}

func TestStampedeIncident(t *testing.T) {
	clouds, cohorts := incidentWorkload()

	for _, c := range clouds {
		defer c.Close()
	}

	result := run(cohorts, clouds)

	t.Logf("")
	t.Logf("=== incident replay: %d servers, max-concurrency %d, budget %s ===",
		result.total, maxConcurrency, reconcileDeadline)
	t.Logf("wall clock         %s", result.elapsed.Round(time.Millisecond))
	t.Logf("throughput         %.1f reconciles/sec", float64(result.total)/result.elapsed.Seconds())
	t.Logf("latency            p50 %s  p95 %s  p99 %s  max %s",
		result.percentile(0.5), result.percentile(0.95), result.percentile(0.99), result.percentile(1))
	t.Logf("keystone logins    %d", result.logins())
	t.Logf("nova list calls    %d", result.novaCalls())
	t.Logf("instance rows scanned %d", result.rows())
	t.Logf("detail records returned %d", result.emitted())

	type tally struct {
		total, ok int
		classes   map[string]int
	}

	byCohort := map[string]*tally{}

	for _, o := range result.results {
		entry, ok := byCohort[o.label]
		if !ok {
			entry = &tally{classes: map[string]int{}}
			byCohort[o.label] = entry
		}

		entry.total++

		if o.ok {
			entry.ok++
		} else {
			entry.classes[o.class]++
		}
	}

	labels := make([]string, 0, len(byCohort))
	for label := range byCohort {
		labels = append(labels, label)
	}

	sort.Strings(labels)

	t.Logf("")
	t.Logf("--- failure rate by cohort (observed on 26 Aug: 73%% / 9%% / 0%%) ---")

	for _, label := range labels {
		entry := byCohort[label]
		failed := entry.total - entry.ok

		t.Logf("%-14s %5d servers  %5d failed  %5.1f%%", label, entry.total, failed,
			100*float64(failed)/float64(entry.total))

		classes := make([]string, 0, len(entry.classes))
		for class := range entry.classes {
			classes = append(classes, class)
		}

		sort.Strings(classes)

		for _, class := range classes {
			t.Logf("                 %-44s %5d", class, entry.classes[class])
		}
	}

	t.Logf("")
	t.Logf("--- provider load ---")

	for _, c := range result.clouds {
		for _, s := range []*serviceModel{c.keystone, c.nova} {
			t.Logf("%-18s served %6d  shed(503) %5d  timeout(504) %5d  peak queue %4d  busy %s",
				s.name, s.served.Load(), s.shed.Load(), s.expired.Load(), s.peakQueue.Load(),
				time.Duration(s.busyTime.Load()).Round(time.Millisecond))
		}

		t.Logf("%-18s rows scanned %d, detail records returned %d",
			c.name+"/nova", c.nova.rows.Load(), c.nova.emitted.Load())
	}
}

// ---------------------------------------------------------------------------
// Scaling sweep
// ---------------------------------------------------------------------------

// sweepSizes is the project sizes to walk, overridable so the fixed code can be
// pushed past the point the unfixed code can be measured at in any sane time.
func sweepSizes() []int {
	raw := os.Getenv("STAMPEDE_SIZES")
	if raw == "" {
		return []int{250, 500, 1000, 2000, 4000}
	}

	sizes := []int{}

	for _, field := range strings.Split(raw, ",") {
		size, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil {
			panic(err)
		}

		sizes = append(sizes, size)
	}

	return sizes
}

// TestStampedeScaling resyncs a single project of increasing size, which is the
// population the cost actually scales with, and reports where the resync stops
// completing inside the per-reconcile budget.
func TestStampedeScaling(t *testing.T) {
	t.Logf("")
	t.Logf("=== scaling: one project, one credential, max-concurrency %d, budget %s ===",
		maxConcurrency, reconcileDeadline)
	t.Logf("%8s %11s %9s %9s %13s %13s %10s",
		"servers", "wall", "failed", "logins", "rows scanned", "records ret", "p99")

	for _, size := range sweepSizes() {
		func() {
			c := newCloud("region", map[string]int{"project": size})
			defer c.Close()

			cohorts := []cohort{{
				label:   "project",
				cloud:   c,
				project: "project",
				userID:  "region-admin",
				servers: size,
			}}

			result := run(cohorts, []*cloud{c})

			t.Logf("%8d %11s %8.1f%% %9d %13d %13d %10s",
				size,
				result.elapsed.Round(time.Millisecond),
				100*float64(result.failed())/float64(result.total),
				result.logins(),
				result.rows(),
				result.emitted(),
				result.percentile(0.99))
		}()
	}
}

// ---------------------------------------------------------------------------
// Monitor walk
// ---------------------------------------------------------------------------

// monitorCycle is one pass of the health monitor over every server, which
// pkg/monitor/health/server/check.go performs SEQUENTIALLY, once per
// --poll-period. Concurrency of one is the whole point: a collapse that merges
// callers overlapping in time merges nothing here, so this path sees only the
// change in what a single read costs.
//
// batched models the alternative shape: one read per identity per cycle, indexed
// by name in memory, which is what the data wants and what an observation-only
// walk is allowed to do.
func monitorCycle(ctx context.Context, cohorts []cohort, batched bool) (time.Duration, int) {
	start := time.Now()
	failures := 0

	for _, c := range cohorts {
		for index := range c.servers {
			// A batched walk pays one provider read for the whole cohort; the
			// remaining servers are resolved from it in memory.
			if batched && index > 0 {
				continue
			}

			if err := monitorRead(ctx, c, index); err != nil {
				failures++
			}
		}
	}

	return time.Since(start), failures
}

// monitorRead is what one server costs the health monitor:
// Checker.checkServer reaches Provider.UpdateServerState, which builds a single
// compute client and reads the server. Unlike a reconcile there is no network
// client, so the monitor pays ONE login per server, not two.
func monitorRead(ctx context.Context, c cohort, index int) error {
	credential := openstack.NewPasswordProvider(c.cloud.identityURL, c.userID, "password", c.project)

	compute, err := openstack.NewComputeClient(ctx, credential, nil)
	if err != nil {
		return err
	}

	_, err = compute.GetServer(ctx, stampedeServerFixture(c.project, index))

	return err
}

// stampedeServerFixture is the minimum a Server needs for both the read and the
// create path: a name to resolve by, and an image and flavor to submit.
func stampedeServerFixture(project string, index int) *unikornv1.Server {
	return &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				coreconstants.NameLabel: stampedeServerName(project, index),
			},
		},
		Spec: unikornv1.ServerSpec{
			Image:    &unikornv1.ServerImage{ID: idstest.MustParseImageID("bbbbbbbb-0000-0000-0000-000000000001")},
			FlavorID: idstest.MustParseFlavorID("bbbbbbbb-0000-0000-0000-000000000002"),
		},
	}
}

func TestStampedeMonitor(t *testing.T) {
	for _, c := range []struct {
		name    string
		batched bool
	}{
		{name: "PerServer"},
		{name: "Batched", batched: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			clouds, cohorts := incidentWorkload()

			for _, cloud := range clouds {
				defer cloud.Close()
			}

			total := 0
			for _, cohort := range cohorts {
				total += cohort.servers
			}

			// No per-reconcile deadline: the monitor has no context budget, it
			// just falls behind its ticker.
			elapsed, failures := monitorCycle(t.Context(), cohorts, c.batched)

			var rows, emitted, calls, logins int64

			for _, cloud := range clouds {
				rows += cloud.nova.rows.Load()
				emitted += cloud.nova.emitted.Load()
				calls += cloud.nova.served.Load()
				logins += cloud.keystone.served.Load()
			}

			t.Logf("")
			t.Logf("=== monitor cycle (%s): %d servers, sequential, poll period %s ===",
				c.name, total, pollPeriod)
			t.Logf("cycle wall clock        %s", elapsed.Round(time.Millisecond))
			t.Logf("fits in poll period     %t (%.1f× the period)", elapsed < pollPeriod,
				elapsed.Seconds()/pollPeriod.Seconds())
			t.Logf("keystone logins         %d", logins)
			t.Logf("nova list calls         %d", calls)
			t.Logf("instance rows scanned   %d", rows)
			t.Logf("detail records returned %d", emitted)
			t.Logf("failures                %d", failures)
		})
	}
}

// ---------------------------------------------------------------------------
// Create burst
// ---------------------------------------------------------------------------

// TestStampedeCreateBurst is the workload where the mutation epoch works against
// the read collapse. Every successful create retires the flights opened before
// it, so a bulk create into one project through one credential shares nothing:
// each server's create gate reads a project that the previous create has just
// grown. This is the case the resync runs do not exercise, and the one where the
// unfiltered read could plausibly cost more than the filter it replaced.
func TestStampedeCreateBurst(t *testing.T) {
	for _, size := range sweepSizes() {
		c := newCloud("region", map[string]int{"project": 0})

		cohorts := []cohort{{
			label:   "create",
			cloud:   c,
			project: "project",
			userID:  "region-admin",
			servers: size,
		}}

		result := run(cohorts, []*cloud{c})

		t.Logf("%8d %11s %8.1f%% %9d %13d %13d %10s",
			size,
			result.elapsed.Round(time.Millisecond),
			100*float64(result.failed())/float64(result.total),
			result.logins(),
			result.rows(),
			result.emitted(),
			result.percentile(0.99))

		c.Close()
	}
}
