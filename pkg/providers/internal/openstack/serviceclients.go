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
	"reflect"
	"sync"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type openStackClients struct {
	// client is Kubernetes client.
	client client.Client

	// DO NOT USE DIRECTLY, CALL AN ACCESSOR.
	_identity *IdentityClient
	_compute  *ComputeClient
	_image    *ImageClient
	_network  NetworkingInterface

	// region is the current region configuration.
	_region *unikornv1.Region
	// secret is the current region secret.
	_secret *corev1.Secret
	// credentials hold cloud identity information.
	_credentials *providerCredentials

	lock sync.Mutex
}

// serviceClientRefresh updates clients if they need to e.g. in the event
// of a configuration update.
// NOTE: you MUST get the lock before calling this function.
//
//nolint:cyclop
func (c *openStackClients) serviceClientRefresh(ctx context.Context) error {
	refresh := false

	region := &unikornv1.Region{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c._region.Namespace, Name: c._region.Name}, region); err != nil {
		return err
	}

	// If anything changes with the configuration, referesh the clients as they may
	// do caching.
	if !reflect.DeepEqual(region.Spec.Openstack, c._region.Spec.Openstack) {
		refresh = true
	}

	secretkey := client.ObjectKey{
		Namespace: region.Spec.Openstack.ServiceAccountSecret.Namespace,
		Name:      region.Spec.Openstack.ServiceAccountSecret.Name,
	}

	secret := &corev1.Secret{}

	if err := c.client.Get(ctx, secretkey, secret); err != nil {
		return err
	}

	// If the secret hasn't beed read yet, or has changed e.g. credential rotation
	// then refresh the clients as they cache the API token.
	if c._secret == nil || !reflect.DeepEqual(secret.Data, c._secret.Data) {
		refresh = true
	}

	// Nothing to do, use what's there.
	if !refresh {
		return nil
	}

	// Create the core credential provider.
	domainID, ok := secret.Data["domain-id"]
	if !ok {
		return fmt.Errorf("%w: domain-id", coreerrors.ErrKey)
	}

	userID, ok := secret.Data["user-id"]
	if !ok {
		return fmt.Errorf("%w: user-id", coreerrors.ErrKey)
	}

	password, ok := secret.Data["password"]
	if !ok {
		return fmt.Errorf("%w: password", coreerrors.ErrKey)
	}

	projectID, ok := secret.Data["project-id"]
	if !ok {
		return fmt.Errorf("%w: project-id", coreerrors.ErrKey)
	}

	credentials := &providerCredentials{
		endpoint:  region.Spec.Openstack.Endpoint,
		domainID:  string(domainID),
		projectID: string(projectID),
		userID:    string(userID),
		password:  string(password),
	}

	// The identity client needs to have "manager" powers, so it create projects and
	// users within a domain without full admin.
	identity, err := NewIdentityClient(ctx, NewDomainScopedPasswordProvider(region.Spec.Openstack.Endpoint, string(userID), string(password), string(domainID)))
	if err != nil {
		return err
	}

	// Everything else gets a default view when bound to a project as a "member".
	// Sadly, domain scoped accesses do not work by default any longer.
	providerClient := NewPasswordProvider(region.Spec.Openstack.Endpoint, string(userID), string(password), string(projectID))

	compute, err := NewComputeClient(ctx, providerClient, region.Spec.Openstack.Compute)
	if err != nil {
		return err
	}

	image, err := NewImageClient(ctx, providerClient, region.Spec.Openstack.Image)
	if err != nil {
		return err
	}

	network, err := NewNetworkClient(ctx, providerClient, region.Spec.Openstack.Network)
	if err != nil {
		return err
	}

	// Save the current configuration for checking next time.
	c._region = region
	c._secret = secret
	c._credentials = credentials

	// Seve the clients
	c._identity = identity
	c._compute = compute
	c._image = image
	c._network = network

	return nil
}

// regionRefresh fetches the underlying objects, and possibly the service clients,
// then returns a consistent Region object and credentials. Unlike regionSnapshot, this may return
// an error if the refresh fails.
func (c *openStackClients) regionRefresh(ctx context.Context) (*unikornv1.Region, *providerCredentials, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	err := c.serviceClientRefresh(ctx)

	return c._region, c._credentials, err
}

func (c *openStackClients) regionSnapshot() (*unikornv1.Region, *providerCredentials) {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c._region, c._credentials
}

// identity returns an admin-level identity client.
func (c *openStackClients) identity(ctx context.Context) (*IdentityClient, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return c._identity, nil
}

// compute returns an admin-level compute client.
func (c *openStackClients) compute(ctx context.Context) (ComputeInterface, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return c._compute, nil
}

// identity returns an admin-level image client.
func (c *openStackClients) image(ctx context.Context) (*ImageClient, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return c._image, nil
}

// identity returns an admin-level network client.
func (c *openStackClients) network(ctx context.Context) (NetworkingInterface, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.serviceClientRefresh(ctx); err != nil {
		return nil, err
	}

	return c._network, nil
}
