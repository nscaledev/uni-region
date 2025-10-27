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

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	"github.com/unikorn-cloud/core/pkg/server/util"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func convertV2(in *regionv1.Network) *openapi.NetworkV2Read {
	return &openapi.NetworkV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.NetworkV2Spec{
			Prefix:         in.Spec.Prefix.String(),
			DnsNameservers: convertIPv4List(in.Spec.DNSNameservers),
		},
		Status: openapi.NetworkV2Status{
			RegionId: in.Labels[constants.RegionLabel],
		},
	}
}

func convertV2List(in *regionv1.NetworkList) openapi.NetworksV2Read {
	out := make(openapi.NetworksV2Read, len(in.Items))

	for i := range in.Items {
		out[i] = *convertV2(&in.Items[i])
	}

	return out
}

// filterRegionID indicates a resource must be omitted from any output because its
// region is not in the user specified set.
func filterRegionID(query *openapi.RegionIDQueryParameter, resource metav1.Object) bool {
	return query != nil && !slices.Contains(*query, resource.GetLabels()[constants.RegionLabel])
}

// filterProjectID indicates a resource must be omitted from any output because its
// project is not in the user specified set.
func filterProjectID(query *openapi.ProjectIDQueryParameter, resource metav1.Object) bool {
	return query != nil && !slices.Contains(*query, resource.GetLabels()[coreconstants.ProjectLabel])
}

func (c *Client) ListV2Admin(ctx context.Context, organizationID string, params openapi.GetApiV2OrganizationsOrganizationIDNetworksParams) (openapi.NetworksV2Read, error) {
	selector := map[string]string{
		coreconstants.OrganizationLabel:   organizationID,
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	}

	options := &client.ListOptions{
		Namespace:     c.namespace,
		LabelSelector: labels.SelectorFromSet(selector),
	}

	result := &regionv1.NetworkList{}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list networks").WithError(err)
	}

	tagSelector, err := util.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.Network) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) || filterRegionID(params.RegionID, &resource) || filterProjectID(params.ProjectID, &resource)
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.Network) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) ListV2(ctx context.Context, organizationID, projectID string, params openapi.GetApiV2OrganizationsOrganizationIDProjectsProjectIDNetworksParams) (openapi.NetworksV2Read, error) {
	selector := map[string]string{
		coreconstants.OrganizationLabel:   organizationID,
		coreconstants.ProjectLabel:        projectID,
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	}

	options := &client.ListOptions{
		Namespace:     c.namespace,
		LabelSelector: labels.SelectorFromSet(selector),
	}

	result := &regionv1.NetworkList{}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list networks").WithError(err)
	}

	tagSelector, err := util.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.Network) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) || filterRegionID(params.RegionID, &resource)
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.Network) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) GetV2Raw(ctx context.Context, organizationID, projectID, networkID string) (*regionv1.Network, error) {
	result, err := c.GetRaw(ctx, organizationID, projectID, networkID)
	if err != nil {
		return nil, err
	}

	// Only allow access to resources created by this API (temporarily).
	v, ok := result.Labels[constants.ResourceAPIVersionLabel]
	if !ok {
		return nil, errors.HTTPNotFound()
	}

	version, err := constants.UnmarshalAPIVersion(v)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to parse API version")
	}

	if version != 2 {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

func (c *Client) GetV2(ctx context.Context, organizationID, projectID, networkID string) (*openapi.NetworkV2Read, error) {
	result, err := c.GetV2Raw(ctx, organizationID, projectID, networkID)
	if err != nil {
		return nil, err
	}

	return convertV2(result), nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID string, request *openapi.NetworkV2Write, prefix *net.IPNet, dnsNameservers []net.IP) (*regionv1.Network, error) {
	out := &regionv1.Network{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.namespace).
			WithOrganization(organizationID).
			WithProject(projectID).
			WithLabel(constants.RegionLabel, request.Spec.RegionId).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.NetworkSpec{
			Tags:           conversion.GenerateTagList(request.Metadata.Tags),
			Prefix:         generateIPV4Prefix(prefix),
			DNSNameservers: generateIPV4AddressList(dnsNameservers),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}

type createSaga struct {
	client         *Client
	organizationID string
	projectID      string
	request        *openapi.NetworkV2Write

	identity *regionv1.Identity
	network  *regionv1.Network
}

func newCreateSaga(client *Client, organizationID, projectID string, request *openapi.NetworkV2Write) *createSaga {
	return &createSaga{
		client:         client,
		organizationID: organizationID,
		projectID:      projectID,
		request:        request,
	}
}

// validateRequest performs any parsing of input data that JSON schema cannot handle,
// then generated the network.
func (s *createSaga) validateRequest(ctx context.Context) error {
	prefix, err := parseIPV4Prefix(s.request.Spec.Prefix)
	if err != nil {
		return err
	}

	ones, _ := prefix.Mask.Size()

	if ones > 24 {
		return errors.OAuth2InvalidRequest("minimum network prefix size is /24")
	}

	dnsNameservers, err := parseIPV4AddressList(s.request.Spec.DnsNameservers)
	if err != nil {
		return err
	}

	network, err := s.client.generateV2(ctx, s.organizationID, s.projectID, s.request, prefix, dnsNameservers)
	if err != nil {
		return err
	}

	s.network = network

	return nil
}

// createServicePricipal creates the service principal that will own all the infrastructure
// for this network and its children.  Adds a link from the network to the service principal
// so we can find it based on the network and also sets up cascading deletion.
func (s *createSaga) createServicePricipal(ctx context.Context) error {
	request := &openapi.IdentityWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name:        "network-" + s.network.Name,
			Description: ptr.To("Service principal for V2 network " + s.network.Name),
		},
		Spec: openapi.IdentityWriteSpec{
			RegionId: s.request.Spec.RegionId,
		},
	}

	identity, err := identity.New(s.client.client, s.client.namespace).CreateRaw(ctx, s.organizationID, s.projectID, request)
	if err != nil {
		return err
	}

	s.identity = identity

	s.network.Labels[constants.IdentityLabel] = identity.Name

	if err := controllerutil.SetOwnerReference(identity, s.network, s.client.client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return errors.OAuth2ServerError("unable to set resource owner").WithError(err)
	}

	return nil
}

// deleteServicePricipal removes the service principal on error.
// NOTE: you must use the shared delete library call to preserve cascading
// deletion semantics.
func (s *createSaga) deleteServicePricipal(ctx context.Context) error {
	return identity.New(s.client.client, s.client.namespace).Delete(ctx, s.organizationID, s.projectID, s.identity.Name)
}

// createAllocation creates an allocation for the network ID and then attaches
// the allocation ID to the network for persistence.
func (s *createSaga) createAllocation(ctx context.Context) error {
	required := identityapi.ResourceAllocationList{
		{
			Kind:      "networks",
			Committed: 1,
		},
	}

	if err := identityclient.NewAllocations(s.client.client, s.client.identity).Create(ctx, s.network, required); err != nil {
		return err
	}

	return nil
}

func (s *createSaga) deleteAllocation(ctx context.Context) error {
	if err := identityclient.NewAllocations(s.client.client, s.client.identity).Delete(ctx, s.network); err != nil {
		return err
	}

	return nil
}

func (s *createSaga) createNetwork(ctx context.Context) error {
	if err := s.client.client.Create(ctx, s.network); err != nil {
		return errors.OAuth2ServerError("unable to create network").WithError(err)
	}

	return nil
}

func (s *createSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("validate request", s.validateRequest, nil),
		saga.NewAction("create service principal", s.createServicePricipal, s.deleteServicePricipal),
		saga.NewAction("create quota allocation", s.createAllocation, s.deleteAllocation),
		saga.NewAction("create network", s.createNetwork, nil),
	}
}

func (c *Client) CreateV2(ctx context.Context, organizationID, projectID string, request *openapi.NetworkV2Write) (*openapi.NetworkV2Read, error) {
	s := newCreateSaga(c, organizationID, projectID, request)

	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return convertV2(s.network), nil
}

func (c *Client) DeleteV2(ctx context.Context, organizationID, projectID, networkID string) error {
	resource, err := c.GetV2Raw(ctx, organizationID, projectID, networkID)
	if err != nil {
		return err
	}

	if err := identityclient.NewAllocations(c.client, c.identity).Delete(ctx, resource); err != nil {
		return err
	}

	// The V2 API doesn't expose service principals, but they are mapped 1:1 to networks, so as the
	// real root of the tree we actually delete that and allow cascading deletion to do the
	// rest.
	return identity.New(c.client, c.namespace).Delete(ctx, organizationID, projectID, resource.Labels[constants.IdentityLabel])
}
