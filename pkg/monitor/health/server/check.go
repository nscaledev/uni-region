/*
Copyright 2025 the Unikorn Authors.
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

package server

import (
	"context"
	goerrors "errors"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/providers"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Checker for server health.
type Checker struct {
	// client is a Kubernetes client.
	client client.Client
	// namespace is where we are running.
	namespace string
}

// New creates a new helath checker.
func New(client client.Client, namespace string) *Checker {
	return &Checker{
		client:    client,
		namespace: namespace,
	}
}

// checkServer consults the provider for the server health status.
func (c *Checker) checkServer(ctx context.Context, server *unikornv1.Server) error {
	identityID, ok := server.Labels[constants.IdentityLabel]
	if !ok {
		return fmt.Errorf("%w: server %s missing identity label", errors.ErrConsistency, server.Name)
	}

	identity := &unikornv1.Identity{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: identityID}, identity); err != nil {
		return err
	}

	regionID, ok := server.Labels[constants.RegionLabel]
	if !ok {
		return fmt.Errorf("%w: server %s missing region label", errors.ErrConsistency, server.Name)
	}

	provider, err := providers.New(ctx, c.client, c.namespace, regionID)
	if err != nil {
		return err
	}

	updated := server.DeepCopy()

	if err := provider.UpdateServerState(ctx, identity, updated); err != nil {
		return err
	}

	if err := c.client.Status().Patch(ctx, updated, client.MergeFrom(server)); err != nil {
		return err
	}

	return nil
}

// Check does a full health check against all servers on the platform.
// NOTE: this is going to be very heavy weight!
func (c *Checker) Check(ctx context.Context) error {
	servers := &unikornv1.ServerList{}

	options := &client.ListOptions{
		Namespace: c.namespace,
	}

	if err := c.client.List(ctx, servers, options); err != nil {
		return err
	}

	for i := range servers.Items {
		if err := c.checkServer(ctx, &servers.Items[i]); err != nil {
			// If a server is stuck in an error state and has no matching
			// machine in the provider, this will get raised, we don't want
			// to prevent other servers from reconciling their power state
			// due to one bad actor!
			if goerrors.Is(err, errors.ErrResourceNotFound) {
				continue
			}

			return err
		}
	}

	return nil
}
