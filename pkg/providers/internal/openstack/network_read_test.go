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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// neutron is a Keystone and Neutron pair whose network and security group
// lists answer with the names in rows: first the first list, later every
// list after it.  Every request that is not a GET is a write, and fails.
type neutron struct {
	server  *httptest.Server
	project string

	lock  sync.Mutex
	first []string
	later []string

	lists    map[string]int
	projects map[string]string
	writes   atomic.Int64
}

func newNeutron(t *testing.T, first, later []string) *neutron {
	t.Helper()

	n := &neutron{
		project:  fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano()),
		first:    first,
		later:    later,
		lists:    map[string]int{},
		projects: map[string]string{},
	}

	n.server = httptest.NewServer(http.HandlerFunc(n.serve))
	t.Cleanup(n.server.Close)

	return n
}

func (n *neutron) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.URL.Path == "/v3/auth/tokens":
		var auth struct {
			Auth struct {
				Identity struct {
					Password struct {
						User struct {
							ID string `json:"id"`
						} `json:"user"`
					} `json:"password"`
				} `json:"identity"`
			} `json:"auth"`
		}

		_ = json.NewDecoder(r.Body).Decode(&auth)

		user := auth.Auth.Identity.Password.User.ID

		w.Header().Set("X-Subject-Token", "token")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token":{"expires_at":%q,"project":{"id":%q,"name":"p"},"user":{"id":%q,"name":"u"},"catalog":[`+
			`{"id":"n","name":"neutron","type":"network",`+
			`"endpoints":[{"id":"ne","interface":"public","region":"","url":%q}]}]}}`,
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339), n.project, user, n.server.URL+"/network/")
	case r.Method != http.MethodGet:
		n.writes.Add(1)
		w.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprint(w, `{}`)
	case strings.TrimSuffix(r.URL.Path, "/") == "/network":
		_, _ = fmt.Fprintf(w, `{"versions":[{"id":"v2.0","status":"CURRENT","links":[{"rel":"self","href":%q}]}]}`, n.server.URL+"/network/v2.0/")
	case r.URL.Path == "/network/v2.0/networks":
		n.list(w, r, "networks", "network-")
	case r.URL.Path == "/network/v2.0/security-groups":
		n.list(w, r, "security_groups", "securitygroup-")
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{}`)
	}
}

func (n *neutron) list(w http.ResponseWriter, r *http.Request, kind, prefix string) {
	n.lock.Lock()
	n.lists[kind]++
	n.projects[kind] = r.URL.Query().Get("project_id")

	names := n.later
	if n.lists[kind] == 1 {
		names = n.first
	}
	n.lock.Unlock()

	rows := []string{}

	for _, name := range names {
		if filter := r.URL.Query().Get("name"); filter != "" && filter != prefix+name {
			continue
		}

		rows = append(rows, fmt.Sprintf(`{"id":%q,"name":%q}`, "id-"+name, prefix+name))
	}

	_, _ = fmt.Fprintf(w, `{%q:[%s]}`, kind, strings.Join(rows, ","))
}

func (n *neutron) count(kind string) int {
	n.lock.Lock()
	defer n.lock.Unlock()

	return n.lists[kind]
}

// client builds a network client for user, logged in to the project.
func (n *neutron) client(t *testing.T, user string) *NetworkClient {
	t.Helper()

	provider := NewPasswordProvider(n.server.URL+"/v3/", user, "password", n.project)

	client, err := NewNetworkClient(t.Context(), provider, nil)
	require.NoError(t, err)

	return client
}

func network(name string) *unikornv1.Network {
	return &unikornv1.Network{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func securityGroup(name string) *unikornv1.SecurityGroup {
	return &unikornv1.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// TestNeutronReadsAnswerFromTheKeptList pins the cache: every server in a
// project reads the same network and groups, so reads within the TTL pay one
// list of each kind, filtered to the token's project.
func TestNeutronReadsAnswerFromTheKeptList(t *testing.T) {
	t.Parallel()

	n := newNeutron(t, []string{"a", "b"}, []string{"a", "b"})
	client := n.client(t, "user")

	for _, name := range []string{"a", "b", "a"} {
		got, err := client.GetNetwork(t.Context(), network(name))
		require.NoError(t, err)
		require.Equal(t, "network-"+name, got.Name)

		group, err := client.GetSecurityGroup(t.Context(), securityGroup(name))
		require.NoError(t, err)
		require.Equal(t, "securitygroup-"+name, group.Name)
	}

	require.Equal(t, 1, n.count("networks"))
	require.Equal(t, 1, n.count("security_groups"))
	require.Equal(t, n.project, n.projects["networks"], "an admin token lists every project's networks")
	require.Equal(t, n.project, n.projects["security_groups"])
}

// TestNeutronNotFoundOnlyFromAFreshList pins the create gates: the network
// and security group controllers create on not-found, and a kept list can
// predate a resource another process made.
func TestNeutronNotFoundOnlyFromAFreshList(t *testing.T) {
	t.Parallel()

	n := newNeutron(t, []string{"a"}, []string{"a", "b"})
	client := n.client(t, "user")

	_, err := client.GetNetwork(t.Context(), network("a"))
	require.NoError(t, err)

	got, err := client.GetNetwork(t.Context(), network("b"))
	require.NoError(t, err)
	require.Equal(t, "network-b", got.Name)

	_, err = client.GetNetwork(t.Context(), network("missing"))
	require.ErrorIs(t, err, coreerrors.ErrResourceNotFound)
}

// TestNeutronListsAreKeptPerUser pins the key: Neutron shows an admin fields
// a member does not see, so one user's list never answers another's read.
func TestNeutronListsAreKeptPerUser(t *testing.T) {
	t.Parallel()

	n := newNeutron(t, []string{"a"}, []string{"a"})

	for _, user := range []string{"member", "admin", "member"} {
		_, err := n.client(t, user).GetNetwork(t.Context(), network("a"))
		require.NoError(t, err)
	}

	require.Equal(t, 2, n.count("networks"))
}

// TestNeutronWithNoProjectNeverShares pins the fail-closed key.
func TestNeutronWithNoProjectNeverShares(t *testing.T) {
	t.Parallel()

	n := newNeutron(t, []string{"a"}, []string{"a"})
	n.project = ""
	client := n.client(t, "user")

	for range 2 {
		_, err := client.GetNetwork(t.Context(), network("a"))
		require.NoError(t, err)
	}

	require.Equal(t, 2, n.count("networks"), "a client with no project must never be answered from a kept list")
}

// neutronLinesMoved reports whether the project's network and security group
// lists were retired after before.
func neutronLinesMoved(projectID string, before time.Time) (bool, bool) {
	return networkLists.project(projectID).line(time.Time{}).After(before),
		securityGroupLists.project(projectID).line(time.Time{}).After(before)
}

// neutronWrites are the client methods known to write to Neutron.
//
//nolint:gochecknoglobals
var neutronWrites = map[string]bool{
	"CreateNetwork": true, "DeleteNetwork": true, "CreateSubnet": true, "UpdateSubnet": true, "DeleteSubnet": true,
	"CreateRouter": true, "DeleteRouter": true, "AddRouterInterface": true, "RemoveRouterInterface": true,
	"CreateSecurityGroup": true, "DeleteSecurityGroup": true, "CreateSecurityGroupRule": true, "DeleteSecurityGroupRule": true,
	"CreateFloatingIP": true, "DeleteFloatingIP": true, "CreateServerPort": true, "UpdatePort": true, "DeletePort": true,
	"UpdateQuotas": true,
}

// TestEveryNeutronWriteRetiresLists pins that every Neutron write retires the
// project's lists, including one that fails: a failed request may still have
// been acted on, and a port or security group created whose reply was lost
// must not read as absent.  Every client method is called, and one that sends
// a write but is not listed above fails, so a new write is held to the rule.
func TestEveryNeutronWriteRetiresLists(t *testing.T) {
	t.Parallel()

	n := newNeutron(t, nil, nil)
	client := n.client(t, "user")

	value := reflect.ValueOf(client)

	for i := range value.NumMethod() {
		method := value.Type().Method(i)

		before := time.Now()
		writes := n.writes.Load()

		args := make([]reflect.Value, method.Type.NumIn()-1)
		for j := range args {
			args[j] = mutationArgument(t, method.Type.In(j+1), namedServer("server-1"))
		}

		func() {
			defer func() { _ = recover() }()

			value.Method(i).Call(args)
		}()

		networks, groups := neutronLinesMoved(n.project, before)

		if !neutronWrites[method.Name] {
			assert.Equal(t, writes, n.writes.Load(), "%s writes to Neutron and must be listed as a write", method.Name)
			assert.False(t, networks || groups, "%s reads, and must not retire lists", method.Name)

			continue
		}

		assert.True(t, networks && groups, "%s writes, and must retire the lists open before it", method.Name)
	}
}
