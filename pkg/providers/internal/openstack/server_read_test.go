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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// listNova is a Keystone and Nova pair. Tokens are scoped to project, and the
// first server list is held open until hold is closed, so a test can act while a
// list is in flight. Lists after the first answer at once.
type listNova struct {
	server  *httptest.Server
	project string

	// first answers the held first list; later answers every list after it.
	first string
	later string

	lists   atomic.Int64
	entered chan struct{}
	hold    chan struct{}
	// another is closed when a second list arrives, for tests that hold the first
	// only until then.
	another     chan struct{}
	anotherOnce sync.Once

	// mutations counts requests that change a server: anything but a GET under
	// /servers.
	mutations atomic.Int64

	// With holdMutations, the next mutation closes mutating and waits for
	// releaseMutations.
	mutationHold chan struct{}
	mutating     chan struct{}
	mutatingOnce sync.Once
}

func newListNova(t *testing.T, first, later string) *listNova {
	t.Helper()

	nova := &listNova{
		// Unique per run, because the list registry is process wide.
		project: fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano()),
		first:   first,
		later:   later,
		entered: make(chan struct{}),
		hold:    make(chan struct{}),
		another: make(chan struct{}),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Subject-Token", "token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"token":{"expires_at":%q,"project":{"id":%q,"name":"p"},"catalog":[`+
			`{"id":"c","name":"nova","type":"compute",`+
			`"endpoints":[{"id":"ce","interface":"public","region":"","url":%q}]}]}}`,
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339), nova.project, nova.server.URL+"/compute/v2.1")
	})

	mux.HandleFunc("/compute/v2.1/servers/detail", func(w http.ResponseWriter, _ *http.Request) {
		body := nova.later

		if nova.lists.Add(1) == 1 {
			body = nova.first

			close(nova.entered)

			select {
			case <-nova.hold:
			case <-time.After(10 * time.Second):
			}
		} else {
			nova.anotherOnce.Do(func() { close(nova.another) })
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	})

	mux.HandleFunc("/compute/v2.1/servers/nova-1/action", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})

	nova.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && strings.Contains(r.URL.Path, "/servers") {
			nova.mutations.Add(1)

			if nova.mutationHold != nil {
				nova.mutatingOnce.Do(func() { close(nova.mutating) })
				<-nova.mutationHold
			}
		}

		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(nova.server.Close)

	// Never leave a handler parked past the test, or closing the server waits on
	// it for ever.
	t.Cleanup(func() {
		nova.release()

		if nova.mutationHold != nil {
			select {
			case <-nova.mutationHold:
			default:
				close(nova.mutationHold)
			}
		}
	})

	return nova
}

// holdMutations makes the next server action wait for releaseMutations.
func (n *listNova) holdMutations() {
	n.mutationHold = make(chan struct{})
	n.mutating = make(chan struct{})
}

func (n *listNova) releaseMutations() {
	close(n.mutationHold)
}

func (n *listNova) release() {
	select {
	case <-n.hold:
	default:
		close(n.hold)
	}
}

// client builds a compute client for user, logged in to the nova's project.
func (n *listNova) client(t *testing.T, user string) *ComputeClient {
	t.Helper()

	provider := NewPasswordProvider(n.server.URL+"/v3/", user, "password", n.project)

	client, err := NewComputeClient(t.Context(), provider, nil)
	require.NoError(t, err)

	return client
}

func listBody(names ...string) string {
	rows := make([]string, len(names))

	for i, name := range names {
		rows[i] = fmt.Sprintf(`{"id":"nova-%d","name":%q,"status":"ACTIVE"}`, i+1, name)
	}

	return `{"servers":[` + strings.Join(rows, ",") + `]}`
}

func namedServer(name string) *unikornv1.Server {
	return &unikornv1.Server{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{coreconstants.NameLabel: name},
		},
	}
}

// listsNotBefore is the line no list of the client's project may be opened
// before and still answer.
func (c *ComputeClient) listsNotBefore() time.Time {
	p := serverLists.project(c.projectID)

	p.lock.Lock()
	defer p.lock.Unlock()

	return p.notBefore
}

type readResult struct {
	server *servers.Server
	err    error
}

func goGetServer(ctx context.Context, client *ComputeClient, name string) <-chan readResult {
	result := make(chan readResult, 1)

	go func() {
		server, err := client.GetServer(ctx, namedServer(name))
		result <- readResult{server, err}
	}()

	return result
}

func awaitRead(t *testing.T, result <-chan readResult) readResult {
	t.Helper()

	select {
	case r := <-result:
		return r
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the read joined a list it should not have")

		return readResult{}
	}
}

// TestGetServerSharesOneListAcrossConcurrentCallers pins the collapse: concurrent
// reads on one credential pay one project list between them, not one each.
//
// The first list is held until either a second list arrives or a grace period
// passes. Shared, no second list ever arrives; unshared, one arrives at once and
// the count says so.
func TestGetServerSharesOneListAcrossConcurrentCallers(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody("server-1", "server-2"), listBody("server-1", "server-2"))
	client := nova.client(t, "user")

	go func() {
		select {
		case <-nova.another:
		case <-time.After(500 * time.Millisecond):
		}

		nova.release()
	}()

	leader := goGetServer(t.Context(), client, "server-1")

	<-nova.entered

	followers := []<-chan readResult{
		goGetServer(t.Context(), client, "server-1"),
		goGetServer(t.Context(), client, "server-2"),
		goGetServer(t.Context(), client, "server-2"),
	}

	for _, result := range append(followers, leader) {
		r := awaitRead(t, result)
		require.NoError(t, r.err)
	}

	require.EqualValues(t, 1, nova.lists.Load(), "concurrent reads on one credential must share one list")
}

// TestGetServerAfterMutationNeverJoinsAnOlderList pins the create gate. A list
// opened before a mutation may not show what the mutation did, so a read taken
// after it must be answered from a list opened after it, not from that one --
// otherwise a reconcile could be told the server it just created does not
// exist, and create a second one.
func TestGetServerAfterMutationNeverJoinsAnOlderList(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody(), listBody("server-1"))
	client := nova.client(t, "user")

	stale := goGetServer(t.Context(), client, "server-1")

	<-nova.entered

	require.NoError(t, client.StartServer(t.Context(), "nova-1"))

	fresh := goGetServer(t.Context(), client, "server-1")

	// Long enough for the read to reach the list in flight, which is the join
	// this test exists to refuse.
	time.Sleep(200 * time.Millisecond)

	nova.release()

	got := awaitRead(t, fresh)
	require.NoError(t, got.err)
	require.Equal(t, "server-1", got.server.Name)

	old := awaitRead(t, stale)
	require.ErrorIs(t, old.err, coreerrors.ErrResourceNotFound, "the list opened before the mutation is still answered to its own callers")
}

// TestGetServerAfterMutationOnAnotherCredential pins that retiring belongs to
// the project, not the credential. A pinned server is created with the Region
// admin credential and read with the service principal's, both scoped to one
// project, so a mutation on one must retire lists open on the other.
func TestGetServerAfterMutationOnAnotherCredential(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody(), listBody("server-1"))
	reader := nova.client(t, "service-principal")
	writer := nova.client(t, "region-admin")

	stale := goGetServer(t.Context(), reader, "server-1")

	<-nova.entered

	require.NoError(t, writer.StartServer(t.Context(), "nova-1"))

	fresh := goGetServer(t.Context(), reader, "server-1")

	// As above: let the read reach the list in flight before releasing it.
	time.Sleep(200 * time.Millisecond)

	nova.release()

	got := awaitRead(t, fresh)
	require.NoError(t, got.err)
	require.Equal(t, "server-1", got.server.Name)

	awaitRead(t, stale)
}

// TestGetServerAfterMutationNeverReadsAnOlderRow pins the same rule for a row
// that is present: the create-retry gate deletes a server it reads as failed,
// so after a write it must not be answered from a list opened before it that
// still shows the failure.
func TestGetServerAfterMutationNeverReadsAnOlderRow(t *testing.T) {
	t.Parallel()

	nova := newListNova(t,
		`{"servers":[{"id":"nova-1","name":"server-1","status":"ERROR"}]}`,
		`{"servers":[{"id":"nova-1","name":"server-1","status":"ACTIVE"}]}`)
	client := nova.client(t, "user")

	stale := goGetServer(t.Context(), client, "server-1")

	<-nova.entered

	require.NoError(t, client.StartServer(t.Context(), "nova-1"))

	fresh := goGetServer(t.Context(), client, "server-1")

	// Long enough for the read to reach the list in flight.
	time.Sleep(200 * time.Millisecond)

	nova.release()

	got := awaitRead(t, fresh)
	require.NoError(t, got.err)
	require.Equal(t, "ACTIVE", got.server.Status, "a read after a write must not see a row from before it")

	awaitRead(t, stale)
}

// TestGetServerWritesDuringAReadDoNotRelist pins the bound: a reader takes the
// retire line once, so writes landing while its list runs cannot send it round
// again, and a stream of writes cannot keep it re-listing the project.
func TestGetServerWritesDuringAReadDoNotRelist(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody("server-1"), listBody("server-1"))
	client := nova.client(t, "user")

	reader := goGetServer(t.Context(), client, "server-1")

	<-nova.entered

	for range 3 {
		require.NoError(t, client.StartServer(t.Context(), "nova-1"))
	}

	nova.release()

	got := awaitRead(t, reader)
	require.NoError(t, got.err)
	require.EqualValues(t, 1, nova.lists.Load(), "writes after a read began must not make it list again")
}

// TestGetServerAnswersFromTheKeptList pins the cache: reads one after another
// in one project pay one list between them, not one each.
func TestGetServerAnswersFromTheKeptList(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody("server-1", "server-2"), listBody("server-1", "server-2"))
	client := nova.client(t, "user")

	nova.release()

	for _, name := range []string{"server-1", "server-2", "server-1"} {
		got := awaitRead(t, goGetServer(t.Context(), client, name))
		require.NoError(t, got.err)
		require.Equal(t, name, got.server.Name)
	}

	require.EqualValues(t, 1, nova.lists.Load(), "reads within the TTL must be answered from the kept list")
}

// TestGetServerNotFoundOnlyFromAFreshList pins the create gate against the
// cache. A kept list can predate a server someone else made, so a server
// missing from it is looked for again in a list opened after the read began;
// told not-found from the kept list, the gate would create a second.
func TestGetServerNotFoundOnlyFromAFreshList(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody(), listBody("server-1"))
	client := nova.client(t, "user")

	nova.release()

	// Fills the kept list, which does not show server-1.
	require.ErrorIs(t, awaitRead(t, goGetServer(t.Context(), client, "server-2")).err, coreerrors.ErrResourceNotFound)

	got := awaitRead(t, goGetServer(t.Context(), client, "server-1"))
	require.NoError(t, got.err)
	require.Equal(t, "server-1", got.server.Name)
}

// TestGetServerMissingServerKeepsTheList pins that a server missing for good
// costs a list per read of it, and nothing for the rest of its project: a
// not-found does not retire the kept list.
func TestGetServerMissingServerKeepsTheList(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody("server-1"), listBody("server-1"))
	client := nova.client(t, "user")

	nova.release()

	require.NoError(t, awaitRead(t, goGetServer(t.Context(), client, "server-1")).err)
	require.ErrorIs(t, awaitRead(t, goGetServer(t.Context(), client, "missing")).err, coreerrors.ErrResourceNotFound)

	for range 3 {
		require.NoError(t, awaitRead(t, goGetServer(t.Context(), client, "server-1")).err)
	}

	require.EqualValues(t, 2, nova.lists.Load(), "only the missing server's fresh read may list again")
}

// TestGetServerWithNoProjectNeverShares pins the fail-closed key: a token with
// no project has nothing to key on, and an empty key would merge projects.
func TestGetServerWithNoProjectNeverShares(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody("server-1"), listBody("server-1"))
	nova.project = ""
	client := nova.client(t, "user")

	nova.release()

	for range 2 {
		require.NoError(t, awaitRead(t, goGetServer(t.Context(), client, "server-1")).err)
	}

	require.EqualValues(t, 2, nova.lists.Load(), "a client with no project must never be answered from a kept list")
}

// TestGetServerListsAgainOnceTheKeptListExpires pins the sweep: a kept list
// older than the TTL answers no one.
func TestGetServerListsAgainOnceTheKeptListExpires(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody("server-1"), listBody("server-1"))
	client := nova.client(t, "user")

	nova.release()

	require.NoError(t, awaitRead(t, goGetServer(t.Context(), client, "server-1")).err)

	serverLists.project(client.projectID).drop(time.Now().Add(2 * keptListTTL))

	require.NoError(t, awaitRead(t, goGetServer(t.Context(), client, "server-1")).err)

	require.EqualValues(t, 2, nova.lists.Load())
}

// TestGetServerRunsOneListPerProject pins the cap. However many mutations
// land while a list is in flight, a project runs that one list and at most
// one more behind it, so a burst of creates or attachments cannot become as many
// whole-project lists at once.
func TestGetServerRunsOneListPerProject(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody(), listBody("server-1"))
	client := nova.client(t, "user")

	stale := goGetServer(t.Context(), client, "server-1")

	<-nova.entered

	fresh := make([]<-chan readResult, 0, 5)

	for range 5 {
		require.NoError(t, client.StartServer(t.Context(), "nova-1"))

		fresh = append(fresh, goGetServer(t.Context(), client, "server-1"))
	}

	// Long enough for an uncapped read to have opened its own list.
	select {
	case <-nova.another:
		require.FailNow(t, "a second list opened while one was in flight")
	case <-time.After(200 * time.Millisecond):
	}

	nova.release()

	for _, result := range fresh {
		got := awaitRead(t, result)
		require.NoError(t, got.err)
		require.Equal(t, "server-1", got.server.Name)
	}

	awaitRead(t, stale)

	require.EqualValues(t, 2, nova.lists.Load(), "the reads behind the first list must share one list")
}

// TestServerMutationRetiresOnlyOnceReturned pins the ordering the freshness rule
// rests on, for every mutation that retires: lists retire after the request has
// returned. Retired before it, a list could open after the line while the
// request is still in flight, miss its effect, and answer the very caller that
// made it -- for CreateServer, with not-found, and a second server.
func TestServerMutationRetiresOnlyOnceReturned(t *testing.T) {
	t.Parallel()

	for _, name := range listMutations {
		if _, ok := notListMutations[name]; ok {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			nova := newListNova(t, listBody(), listBody())
			client := nova.client(t, "user")

			nova.release()
			nova.holdMutations()

			before := client.listsNotBefore()

			call := clientMethodCall(t, client, name)
			done := make(chan struct{})

			go func() {
				defer close(done)

				call()
			}()

			<-nova.mutating

			require.Equal(t, before, client.listsNotBefore(), "lists must not retire while the request is in flight")

			nova.releaseMutations()

			<-done

			require.True(t, client.listsNotBefore().After(before), "lists must retire once the request has returned")
		})
	}
}

// listMutations are the client methods known to write to a Nova server. A floor
// for the discovery below, and the set the ordering test runs.
//
//nolint:gochecknoglobals
var listMutations = []string{
	"CreateServer", "DeleteServer", "RebootServer", "RebuildServer", "StartServer", "StopServer",
	"CreateImageFromServer", "CreateVolumeAttachment", "DeleteVolumeAttachment",
}

// clientMethodCall prepares a call of the named client method with arguments
// that let it reach Nova. The call discards its result and any panic.
func clientMethodCall(t *testing.T, client *ComputeClient, name string) func() {
	t.Helper()

	method := reflect.ValueOf(client).MethodByName(name)
	require.True(t, method.IsValid(), "no method %s", name)

	server := namedServer("server-1")
	server.Spec.Image = &unikornv1.ServerImage{}

	args := make([]reflect.Value, method.Type().NumIn())

	for i := range args {
		args[i] = mutationArgument(t, method.Type().In(i), server)
	}

	return func() {
		defer func() { _ = recover() }()

		method.Call(args)
	}
}

// TestEveryServerMutationRetiresOpenLists pins that every request that writes
// to a Nova server retires its project's lists, including one that fails,
// because a failed request may still have been acted on. They are found by
// calling every client method and watching what reaches Nova, so a new one is
// held to the rule unless it is exempted here with a reason.
func TestEveryServerMutationRetiresOpenLists(t *testing.T) {
	t.Parallel()

	nova := newListNova(t, listBody(), listBody())
	client := nova.client(t, "user")
	// Discovery calls the readers too; do not hold them.
	nova.release()

	value := reflect.ValueOf(client)
	found := map[string]bool{}

	for i := range value.NumMethod() {
		method := value.Type().Method(i)

		before := client.listsNotBefore()
		mutations := nova.mutations.Load()

		clientMethodCall(t, client, method.Name)()

		if nova.mutations.Load() == mutations {
			continue
		}

		found[method.Name] = true

		retired := client.listsNotBefore().After(before)

		if reason, ok := notListMutations[method.Name]; ok {
			assert.False(t, retired, "%s must not retire open lists: %s", method.Name, reason)

			continue
		}

		assert.True(t, retired, "%s must retire the lists open before it", method.Name)
	}

	// A floor, so the discovery cannot quietly find nothing. Discovery only
	// sees a method that reaches Nova with these arguments, so a new mutation
	// that fails before the request must be added here to be held to the rule.
	for _, name := range listMutations {
		require.True(t, found[name], "%s was not exercised", name)
	}
}

// notListMutations are the writes under /servers that need not retire lists, and why.
//
//nolint:gochecknoglobals
var notListMutations = map[string]string{
	"DeleteServer":        "a list from before it can only show the server still present, see its comment",
	"CreateRemoteConsole": "opening a console changes nothing a list shows",
	"ShowConsoleOutput":   "a read that Nova spells as a server action",
}

// mutationArgument builds an argument of type kind that lets a client method
// reach Nova.
func mutationArgument(t *testing.T, kind reflect.Type, server *unikornv1.Server) reflect.Value {
	t.Helper()

	switch kind {
	case reflect.TypeFor[context.Context]():
		return reflect.ValueOf(t.Context())
	case reflect.TypeFor[*unikornv1.Server]():
		return reflect.ValueOf(server)
	case reflect.TypeFor[*servers.CreateImageOpts]():
		return reflect.ValueOf(&servers.CreateImageOpts{Name: "image"})
	}

	if kind.Kind() == reflect.Pointer {
		return reflect.New(kind.Elem())
	}

	// An empty ID never reaches Nova.
	if kind.Kind() == reflect.String {
		return reflect.ValueOf("x").Convert(kind)
	}

	return reflect.Zero(kind)
}
