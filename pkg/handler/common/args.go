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

package common

import (
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/region/pkg/providers"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClientArgs has the values needed to create handlers and clients.
// The general idea is these things should be either scalars or interfaces
// that can easily be mocked out in tests.
type ClientArgs struct {
	// Client accesses Kubernetes directly.
	Client client.Client

	// Namespace is the namespace we are running in.
	Namespace string

	// Providers gives access to the provider interface.
	Providers providers.Providers

	// Identity is an identity client for RBAC access.
	Identity identityapi.ClientWithResponsesInterface
}

// RetryConflictOnce runs attempt and, if it returns a Kubernetes conflict,
// once more, so a write that raced the guard's read is retried against a
// fresh copy rather than failing the request. A second conflict is returned
// as a 409, leaving the concurrent-write decision to the caller.
func (c ClientArgs) RetryConflictOnce(attempt func() error) error {
	err := attempt()
	if !kerrors.IsConflict(err) {
		return err
	}

	if err = attempt(); kerrors.IsConflict(err) {
		return errors.HTTPConflict().WithError(err)
	}

	return err
}
