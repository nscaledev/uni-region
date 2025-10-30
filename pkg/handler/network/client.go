/*
Copyright 2025 the Unikorn Authors.

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

package network

import (
	"cmp"
	"context"
	"net"
	"slices"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Client provides a restful API for networks.
type Client struct {
	// client ia a Kubernetes client.
	client client.Client
	// namespace we are running in.
	namespace string
	// identity allows quota allocation.
	identity identityclient.APIClientGetter
}

// New creates a new client.
func New(client client.Client, namespace string, identity identityclient.APIClientGetter) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		identity:  identity,
	}
}

// convertIPv4List converts a Kubernetes network list into an API one.
func convertIPv4List(in []unikornv1core.IPv4Address) openapi.Ipv4AddressList {
	out := make(openapi.Ipv4AddressList, len(in))

	for i, ip := range in {
		out[i] = ip.String()
	}

	return out
}

// convert converts a single resource from the Kubernetes representation into the API one.
func (c *Client) convert(in *unikornv1.Network) *openapi.NetworkRead {
	out := &openapi.NetworkRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.NetworkReadSpec{
			RegionId:       in.Labels[constants.RegionLabel],
			Prefix:         in.Spec.Prefix.String(),
			DnsNameservers: convertIPv4List(in.Spec.DNSNameservers),
		},
	}

	// TODO: this exposes provider internals to external services, for CAPO's benefit,
	// Get rid of it to prevent leaking information.
	if in.Status.Openstack != nil {
		out.Spec.Openstack = &openapi.NetworkSpecOpenstack{
			NetworkId: in.Status.Openstack.NetworkID,
			SubnetId:  in.Status.Openstack.SubnetID,
		}
	}

	return out
}

// convertList converts a list of resources from the Kubernetes representation into the API one.
func (c *Client) convertList(in unikornv1.NetworkList) openapi.NetworksRead {
	out := make(openapi.NetworksRead, len(in.Items))

	for i := range in.Items {
		out[i] = *c.convert(&in.Items[i])
	}

	return out
}

func parseIPV4Prefix(in string) (*net.IPNet, error) {
	_, prefix, err := net.ParseCIDR(in)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unable to parse IPv4 prefix").WithError(err)
	}

	return prefix, err
}

func generateIPV4Prefix(in *net.IPNet) *unikornv1core.IPv4Prefix {
	return &unikornv1core.IPv4Prefix{
		IPNet: *in,
	}
}

func parseIPV4Address(in string) (net.IP, error) {
	ip := net.ParseIP(in)
	if ip == nil {
		return nil, errors.OAuth2InvalidRequest("unable to parse IPv4 address")
	}

	return ip, nil
}

func parseIPV4AddressList(in []string) ([]net.IP, error) {
	out := make([]net.IP, len(in))

	for i := range in {
		ip, err := parseIPV4Address(in[i])
		if err != nil {
			return nil, err
		}

		out[i] = ip
	}

	return out, nil
}

func generateIPV4AddressList(in []net.IP) []unikornv1core.IPv4Address {
	out := make([]unikornv1core.IPv4Address, len(in))

	for i := range in {
		out[i] = unikornv1core.IPv4Address{
			IP: in[i],
		}
	}

	return out
}

// generate a new resource from a request.
func (c *Client) generate(ctx context.Context, organizationID, projectID, identityID string, request *openapi.NetworkWrite) (*unikornv1.Network, error) {
	identity, err := identity.New(c.client, c.namespace).GetRaw(ctx, organizationID, projectID, identityID)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to get identity").WithError(err)
	}

	prefix, err := parseIPV4Prefix(request.Spec.Prefix)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unable to parse prefix").WithError(err)
	}

	dnsNameservers, err := parseIPV4AddressList(request.Spec.DnsNameservers)
	if err != nil {
		return nil, err
	}

	out := &unikornv1.Network{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.namespace).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.RegionLabel, identity.Labels[constants.RegionLabel]).WithLabel(constants.IdentityLabel, identityID).Get(),
		Spec: unikornv1.NetworkSpec{
			Tags:           conversion.GenerateTagList(request.Metadata.Tags),
			Provider:       identity.Spec.Provider,
			Prefix:         generateIPV4Prefix(prefix),
			DNSNameservers: generateIPV4AddressList(dnsNameservers),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	// The resource belongs to its identity, for cascading deletion.
	if err := controllerutil.SetOwnerReference(identity, out, c.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, errors.OAuth2ServerError("unable to set resource owner").WithError(err)
	}

	return out, nil
}

// GetRaw gives access to the raw Kubernetes resource.
func (c *Client) GetRaw(ctx context.Context, organizationID, projectID, networkID string) (*unikornv1.Network, error) {
	resource := &unikornv1.Network{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: networkID}, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup network").WithError(err)
	}

	if err := coreutil.AssertProjectOwnership(resource, organizationID, projectID); err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns an ordered list of all resources in scope.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.NetworksRead, error) {
	var result unikornv1.NetworkList

	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{
			coreconstants.OrganizationLabel: organizationID,
		}),
	}

	if err := c.client.List(ctx, &result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list networks").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.Network) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return c.convertList(result), nil
}

// Create instantiates a new resource.
func (c *Client) Create(ctx context.Context, organizationID, projectID, identityID string, request *openapi.NetworkWrite) (*openapi.NetworkRead, error) {
	resource, err := c.generate(ctx, organizationID, projectID, identityID, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("unable to create network").WithError(err)
	}

	return c.convert(resource), nil
}

// Get a resource.
func (c *Client) Get(ctx context.Context, organizationID, projectID, networkID string) (*openapi.NetworkRead, error) {
	result, err := c.GetRaw(ctx, organizationID, projectID, networkID)
	if err != nil {
		return nil, err
	}

	return c.convert(result), nil
}

// Delete a resource.
func (c *Client) Delete(ctx context.Context, organizationID, projectID, networkID string) error {
	result, err := c.GetRaw(ctx, organizationID, projectID, networkID)
	if err != nil {
		return err
	}

	if err := c.client.Delete(ctx, result, util.ForegroundDeleteOptions()); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete network").WithError(err)
	}

	return nil
}
