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
	"fmt"

	"golang.org/x/sync/singleflight"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
)

// joinFlight runs fn at most once per key for every caller that arrives while it
// is in flight, and hands each of them its result.
//
// fn runs detached from whichever caller opened the flight, so a caller that
// hangs up cannot fail the healthy callers that joined; fn must therefore be
// bounded by something else (see providerRequestTimeout). Each caller still stops
// waiting when its own context is done.
//
// DoChan and not Do: Do parks a follower on a WaitGroup it cannot interrupt.
func joinFlight[T any](ctx context.Context, group *singleflight.Group, key, what string, fn func(context.Context) (T, error)) (T, error) {
	detached := context.WithoutCancel(ctx)

	//nolint:nonamedreturns // the deferred recover below has to set the error.
	channel := group.DoChan(key, func() (value any, err error) {
		// singleflight re-panics on a bare goroutine when callers are waiting on
		// a channel, which is unrecoverable and would take the process down.
		// Reconciles and API handlers recover a panic and fail one unit of work;
		// keep that.
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("%w: panic during %s: %v", coreerrors.ErrConsistency, what, recovered)
			}
		}()

		return fn(detached)
	})

	var zero T

	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case outcome := <-channel:
		if outcome.Err != nil {
			return zero, outcome.Err
		}

		value, ok := outcome.Val.(T)
		if !ok {
			return zero, fmt.Errorf("%w: %s returned %T", coreerrors.ErrConsistency, what, outcome.Val)
		}

		return value, nil
	}
}
