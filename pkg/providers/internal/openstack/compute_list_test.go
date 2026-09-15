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

package openstack_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/region/pkg/providers/internal/openstack"
)

// pagedNova serves /servers/detail with Nova's marker pagination: it honours
// limit, advertises a next link while rows remain, and records what it was
// asked for.
type pagedNova struct {
	total  int
	limits []string
}

// intQuery parses a query value, yielding fallback when it is absent.
func intQuery(raw string, fallback int) (int, bool) {
	if raw == "" {
		return fallback, true
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}

	return value, true
}

// page renders rows [start, end) and a next link while rows remain.
func (n *pagedNova) page(host string, start, end, limit int) *strings.Builder {
	out := &strings.Builder{}

	out.WriteString(`{"servers":[`)

	for i := start; i < end; i++ {
		if i > start {
			out.WriteString(",")
		}

		fmt.Fprintf(out, `{"id":"%d","name":"server-%d","status":"ACTIVE"}`, i, i)
	}

	out.WriteString(`]`)

	if end < n.total {
		fmt.Fprintf(out, `,"servers_links":[{"rel":"next","href":"http://%s/servers/detail?limit=%d&marker=%d"}]`,
			host, limit, end-1)
	}

	out.WriteString(`}`)

	return out
}

func (n *pagedNova) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/servers/detail" {
		http.NotFound(w, r)

		return
	}

	query := r.URL.Query()
	n.limits = append(n.limits, query.Get("limit"))

	// The marker is the id of the previous page's last row, and ids here are the
	// row index, so the next page starts one past it.
	start, ok := intQuery(query.Get("marker"), -1)
	if !ok {
		http.Error(w, "bad marker", http.StatusBadRequest)

		return
	}

	start++

	limit, ok := intQuery(query.Get("limit"), n.total+1)
	if !ok || limit <= 0 {
		http.Error(w, "bad limit", http.StatusBadRequest)

		return
	}

	out := n.page(r.Host, start, min(start+limit, n.total), limit)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(out.String()))
}

// TestListServersReturnsEveryPage walks the page boundary in both directions.
// A truncating read is the dangerous failure: every server past the cut misses
// the observer's index and is projected as absent, so a large identity would see
// a mass false-absence event.
func TestListServersReturnsEveryPage(t *testing.T) {
	t.Parallel()

	// 250 is serverListPageSize, so these straddle one, two and many pages.
	for _, total := range []int{0, 1, 249, 250, 251, 500, 501, 1750} {
		t.Run(strconv.Itoa(total), func(t *testing.T) {
			t.Parallel()

			nova := &pagedNova{total: total}

			server := httptest.NewServer(nova)
			defer server.Close()

			list, err := openstack.NewTestComputeClient(server.URL + "/").ListServers(t.Context())
			require.NoError(t, err)
			require.Len(t, list, total)

			// Complete and in order, so nothing was skipped or repeated.
			for i, item := range list {
				require.Equal(t, fmt.Sprintf("server-%d", i), item.Name)
			}
		})
	}
}

// TestListServersBoundsThePageSize pins that the read asks for a bounded page.
// Without it gophercloud takes whatever Nova's osapi_max_limit hands over, and
// the decode peak scales with the project rather than the page — which is what
// the memory limit is sized against.
func TestListServersBoundsThePageSize(t *testing.T) {
	t.Parallel()

	nova := &pagedNova{total: 600}

	server := httptest.NewServer(nova)
	defer server.Close()

	list, err := openstack.NewTestComputeClient(server.URL + "/").ListServers(t.Context())
	require.NoError(t, err)
	require.Len(t, list, 600)

	require.NotEmpty(t, nova.limits)

	for _, limit := range nova.limits {
		require.Equal(t, "250", limit, "every request must carry the bounded page size")
	}

	require.Len(t, nova.limits, 3, "600 rows at 250 a page is three requests")
}
