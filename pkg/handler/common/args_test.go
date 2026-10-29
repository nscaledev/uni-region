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

package common_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/handler/common"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// newConflict returns a Kubernetes conflict error as a write against a stale
// resource version would.
func newConflict() error {
	return kerrors.NewConflict(schema.GroupResource{Group: "region.unikorn-cloud.org", Resource: "networks"}, "test", nil)
}

// errBoom is a plain non-conflict error.
var errBoom = errors.New("boom")

// TestRetryConflictOnceRetriesOnceOnConflict covers a write that lost a race:
// the guard's read is re-run against a fresh copy and the retry succeeds.
func TestRetryConflictOnceRetriesOnceOnConflict(t *testing.T) {
	t.Parallel()

	attempts := 0

	err := common.ClientArgs{}.RetryConflictOnce(func() error {
		attempts++

		if attempts == 1 {
			return newConflict()
		}

		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 2, attempts)
}

// TestRetryConflictOnceReturns409OnSecondConflict covers a conflict that
// survives the retry: the caller gets a 409 and decides what to do.
func TestRetryConflictOnceReturns409OnSecondConflict(t *testing.T) {
	t.Parallel()

	err := common.ClientArgs{}.RetryConflictOnce(newConflict)
	require.Error(t, err)
	require.True(t, coreerrors.IsConflict(err), "expected 409 conflict, got: %v", err)
}

// TestRetryConflictOncePassesNonConflictThrough covers any other error: it is
// returned as-is and the attempt is not retried.
func TestRetryConflictOncePassesNonConflictThrough(t *testing.T) {
	t.Parallel()

	attempts := 0

	err := common.ClientArgs{}.RetryConflictOnce(func() error {
		attempts++

		return errBoom
	})
	require.ErrorIs(t, err, errBoom)
	require.Equal(t, 1, attempts)
}
