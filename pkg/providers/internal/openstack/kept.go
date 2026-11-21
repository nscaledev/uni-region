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

package openstack

import (
	"context"
	"sync"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"golang.org/x/sync/singleflight"

	"github.com/unikorn-cloud/core/pkg/errors"
)

// keptListTTL is how long a finished list answers readers that have not
// retired it.  Freshness is not a goal: a poll period of staleness is fine,
// decoding the same rows once per resource per period is not.  See the
// README's Kept Lists section.
const keptListTTL = time.Minute

// keptList is a project's list of one kind and when it was opened.
type keptList[T any] struct {
	opened time.Time
	rows   []T
}

// index is the position of the first row match accepts, or -1.  By pointer:
// a row is large, and a project's rows are scanned on every read.
func (l *keptList[T]) index(match func(*T) bool) int {
	for i := range l.rows {
		if match(&l.rows[i]) {
			return i
		}
	}

	return -1
}

// keptProject is one project's kept lists, one per reader, and the line no
// answer may cross.
//
// A reader MUST only be answered from a list opened after its own floor and
// after notBefore as it stood when the read began, and only a list opened
// after a read began may answer it not-found.  Without that a reconcile could
// be told the resource it just created does not exist, and create a second.
// The line is taken once per read, so a stream of writes cannot keep a reader
// re-listing.
type keptProject[T any] struct {
	lock sync.Mutex
	// notBefore moves forward, once each write in the project has returned,
	// to the time it returned.
	notBefore time.Time
	kept      map[string]*keptList[T]
}

// line is the oldest a list may be opened and answer a read with floor that
// begins now.
func (p *keptProject[T]) line(floor time.Time) time.Time {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.notBefore.After(floor) {
		return p.notBefore
	}

	return floor
}

// answer returns reader's kept list if it was opened after line.  A retire
// drops the kept lists, so none is older than notBefore.
func (p *keptProject[T]) answer(reader string, line time.Time) *keptList[T] {
	p.lock.Lock()
	defer p.lock.Unlock()

	if kept, ok := p.kept[reader]; ok && kept.opened.After(line) {
		return kept
	}

	return nil
}

func (p *keptProject[T]) keep(reader string, list *keptList[T]) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if !list.opened.After(p.notBefore) {
		return
	}

	if kept, ok := p.kept[reader]; !ok || list.opened.After(kept.opened) {
		p.kept[reader] = list
	}
}

func (p *keptProject[T]) retire(now time.Time) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if now.After(p.notBefore) {
		p.notBefore = now
	}

	for reader, kept := range p.kept {
		if !kept.opened.After(p.notBefore) {
			delete(p.kept, reader)
		}
	}
}

// drop forgets kept lists once they can answer no one.
func (p *keptProject[T]) drop(now time.Time) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for reader, kept := range p.kept {
		if now.Sub(kept.opened) > keptListTTL {
			delete(p.kept, reader)
		}
	}
}

// keptLists holds one kind's lists, one entry per project, never removed: a
// reader holding an entry must see every later retire of its project.  At
// most one list runs at a time per project and reader.
type keptLists[T any] struct {
	what string

	lock     sync.Mutex
	projects map[string]*keptProject[T]
	flights  singleflight.Group
}

func newKeptLists[T any](what string) *keptLists[T] {
	return &keptLists[T]{what: what, projects: map[string]*keptProject[T]{}}
}

func (r *keptLists[T]) project(projectID string) *keptProject[T] {
	r.lock.Lock()
	defer r.lock.Unlock()

	p, ok := r.projects[projectID]
	if !ok {
		p = &keptProject[T]{kept: map[string]*keptList[T]{}}
		r.projects[projectID] = p
	}

	return p
}

// retire stops every list of the project opened before now answering a read
// that begins after.
func (r *keptLists[T]) retire(projectID string) {
	if projectID != "" {
		r.project(projectID).retire(time.Now())
	}
}

// sweep drops kept lists that have outlived the TTL, so a quiet project does
// not hold its rows.
func (r *keptLists[T]) sweep(now time.Time) {
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, p := range r.projects {
		p.drop(now)
	}
}

// since returns the project's rows from a list opened after floor and after
// the project's last retire, kept or shared with every caller with the same
// reader that it also satisfies.  An empty project MUST NOT be passed: it
// would merge projects.
//
// A caller that joins a list opened too early asks again.  The key is free
// once that list has finished, so the next list opens after the caller's
// call, and so after its line: at most two rounds.
//
// The result is shared and kept: callers MUST NOT modify it.
func (r *keptLists[T]) since(ctx context.Context, projectID, reader string, floor time.Time, list func(context.Context) ([]T, error)) (*keptList[T], error) {
	p := r.project(projectID)

	line := p.line(floor)

	for {
		if kept := p.answer(reader, line); kept != nil {
			return kept, nil
		}

		// Kept inside the flight, so a caller that hangs up cannot skip it.
		kept, err := joinFlight(ctx, &r.flights, projectID+"\x00"+reader, r.what, func(ctx context.Context) (*keptList[T], error) {
			kept := &keptList[T]{opened: time.Now()}

			rows, err := list(ctx)
			if err != nil {
				return nil, err
			}

			kept.rows = rows

			p.keep(reader, kept)
			r.sweep(time.Now())

			return kept, nil
		})
		if err != nil {
			return nil, err
		}

		if kept.opened.After(line) {
			return kept, nil
		}
	}
}

// find returns a copy of the row match accepts.  Only a list opened after the
// call began may answer not-found: create gates act on it, and a kept list can
// predate a resource someone else made.  The copy shares nested values with
// the kept list, so callers MUST NOT write to them.
func (r *keptLists[T]) find(ctx context.Context, projectID, reader string, list func(context.Context) ([]T, error), match func(*T) bool) (*T, error) {
	start := time.Now()

	kept, err := r.since(ctx, projectID, reader, start.Add(-keptListTTL), list)
	if err != nil {
		return nil, err
	}

	index := kept.index(match)

	if index < 0 && !kept.opened.After(start) {
		if kept, err = r.since(ctx, projectID, reader, start, list); err != nil {
			return nil, err
		}

		index = kept.index(match)
	}

	if index < 0 {
		return nil, errors.ErrResourceNotFound
	}

	found := kept.rows[index]

	return &found, nil
}

// authScope is the project and user the client's token is scoped to, either
// empty if it has none.
func authScope(client *gophercloud.ProviderClient) (string, string) {
	result, ok := client.GetAuthResult().(interface {
		ExtractProject() (*tokens.Project, error)
		ExtractUser() (*tokens.User, error)
	})
	if !ok {
		return "", ""
	}

	var projectID, userID string

	if project, err := result.ExtractProject(); err == nil && project != nil {
		projectID = project.ID
	}

	if user, err := result.ExtractUser(); err == nil && user != nil {
		userID = user.ID
	}

	return projectID, userID
}
