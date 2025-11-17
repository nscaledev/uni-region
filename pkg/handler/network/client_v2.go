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
	"encoding/json"
	"net"
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	"github.com/unikorn-cloud/region/pkg/handler/identity"
	"github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func convertRoute(in *regionv1.Route) *openapi.Route {
	return &openapi.Route{
		Prefix:  in.Prefix.String(),
		Nexthop: in.NextHop.String(),
	}
}

func convertRoutes(in []regionv1.Route) *openapi.Routes {
	if len(in) == 0 {
		return nil
	}

	out := make(openapi.Routes, len(in))

	for i := range in {
		out[i] = *convertRoute(&in[i])
	}

	return &out
}

func convertV2(in *regionv1.Network) *openapi.NetworkV2Read {
	return &openapi.NetworkV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.NetworkV2Spec{
			DnsNameservers: convertIPv4List(in.Spec.DNSNameservers),
			Routes:         convertRoutes(in.Spec.Routes),
		},
		Status: openapi.NetworkV2Status{
			RegionId: in.Labels[constants.RegionLabel],
			Prefix:   in.Spec.Prefix.String(),
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

func (c *Client) ListV2(ctx context.Context, params openapi.GetApiV2NetworksParams) (openapi.NetworksV2Read, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	var err error

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector, util.OrganizationIDQuery(params.OrganizationID), util.ProjectIDQuery(params.ProjectID))
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to add identity label selector").WithError(err)
	}

	selector, err = util.AddRegionIDQuery(selector, params.RegionID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to add region label selector").WithError(err)
	}

	options := &client.ListOptions{
		Namespace:     c.namespace,
		LabelSelector: selector,
	}

	result := &regionv1.NetworkList{}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("unable to list networks").WithError(err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.Network) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) ||
			rbac.AllowProjectScope(ctx, "region:networks:v2", identityapi.Read, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.Network) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) GetV2Raw(ctx context.Context, networkID string) (*regionv1.Network, error) {
	result := &regionv1.Network{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: networkID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to lookup network").WithError(err)
	}

	if err := rbac.AllowProjectScope(ctx, "region:networks:v2", identityapi.Read, result.Labels[coreconstants.OrganizationLabel], result.Labels[coreconstants.ProjectLabel]); err != nil {
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

func (c *Client) GetV2(ctx context.Context, networkID string) (*openapi.NetworkV2Read, error) {
	result, err := c.GetV2Raw(ctx, networkID)
	if err != nil {
		return nil, err
	}

	return convertV2(result), nil
}

// convertCreateToUpdateRequest marshals a create request into an update request
// that can be used with generate().  Updates are a subset of creates (without the
// immutable bits).
func convertCreateToUpdateRequest(in *openapi.NetworkV2Create) (*openapi.NetworkV2Update, error) {
	t, err := json.Marshal(in)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to marshal request").WithError(err)
	}

	out := &openapi.NetworkV2Update{}

	if err := json.Unmarshal(t, out); err != nil {
		return nil, errors.OAuth2ServerError("failed to unmarshal request").WithError(err)
	}

	return out, nil
}

func generateRoutes(in *openapi.Routes) ([]regionv1.Route, error) {
	if in == nil {
		return nil, nil
	}

	out := make([]regionv1.Route, len(*in))

	for i, route := range *in {
		_, prefix, err := net.ParseCIDR(route.Prefix)
		if err != nil {
			return nil, errors.OAuth2InvalidRequest("failed to parse route prefix").WithError(err)
		}

		nextHop := net.ParseIP(route.Nexthop)
		if nextHop == nil {
			return nil, errors.OAuth2InvalidRequest("failed to parse route next-hop").WithError(err)
		}

		out[i].Prefix.IPNet = *prefix
		out[i].NextHop.IP = nextHop
	}

	return out, nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID, regionID string, request *openapi.NetworkV2Update, prefix *net.IPNet) (*regionv1.Network, error) {
	dnsNameservers, err := parseIPV4AddressList(request.Spec.DnsNameservers)
	if err != nil {
		return nil, err
	}

	routes, err := generateRoutes(request.Spec.Routes)
	if err != nil {
		return nil, err
	}

	out := &regionv1.Network{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.namespace).
			WithOrganization(organizationID).
			WithProject(projectID).
			WithLabel(constants.RegionLabel, regionID).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.NetworkSpec{
			Tags:           conversion.GenerateTagList(request.Metadata.Tags),
			Prefix:         generateIPV4Prefix(prefix),
			DNSNameservers: generateIPV4AddressList(dnsNameservers),
			Routes:         routes,
		},
	}

	if err := util.InjectUserPrincipal(ctx, organizationID, projectID); err != nil {
		return nil, errors.OAuth2ServerError("unable to set principal information").WithError(err)
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}

type createSaga struct {
	client  *Client
	request *openapi.NetworkV2Create

	identity *regionv1.Identity
	network  *regionv1.Network
}

func newCreateSaga(client *Client, request *openapi.NetworkV2Create) *createSaga {
	return &createSaga{
		client:  client,
		request: request,
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

	updateRequest, err := convertCreateToUpdateRequest(s.request)
	if err != nil {
		return err
	}

	network, err := s.client.generateV2(ctx, s.request.Spec.OrganizationId, s.request.Spec.ProjectId, s.request.Spec.RegionId, updateRequest, prefix)
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

	identity, err := identity.New(s.client.client, s.client.namespace).CreateRaw(ctx, s.request.Spec.OrganizationId, s.request.Spec.ProjectId, request)
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
	return identity.New(s.client.client, s.client.namespace).Delete(ctx, s.request.Spec.OrganizationId, s.request.Spec.ProjectId, s.identity.Name)
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

func (c *Client) CreateV2(ctx context.Context, request *openapi.NetworkV2Create) (*openapi.NetworkV2Read, error) {
	if err := rbac.AllowProjectScope(ctx, "region:networks:v2", identityapi.Create, request.Spec.OrganizationId, request.Spec.ProjectId); err != nil {
		return nil, err
	}

	s := newCreateSaga(c, request)

	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return convertV2(s.network), nil
}

func (c *Client) Update(ctx context.Context, networkID string, request *openapi.NetworkV2Update) (*openapi.NetworkV2Read, error) {
	current, err := c.GetV2Raw(ctx, networkID)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScope(ctx, "region:networks:v2", identityapi.Delete, current.Labels[coreconstants.OrganizationLabel], current.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.OAuth2InvalidRequest("network is being deleted")
	}

	organizationID := current.Labels[coreconstants.OrganizationLabel]
	projectID := current.Labels[coreconstants.ProjectLabel]
	regionID := current.Labels[constants.RegionLabel]

	required, err := c.generateV2(ctx, organizationID, projectID, regionID, request, &current.Spec.Prefix.IPNet)
	if err != nil {
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("unable to update network").WithError(err)
	}

	return convertV2(updated), nil
}

func (c *Client) DeleteV2(ctx context.Context, networkID string) error {
	resource, err := c.GetV2Raw(ctx, networkID)
	if err != nil {
		return err
	}

	organizationID := resource.Labels[coreconstants.OrganizationLabel]
	projectID := resource.Labels[coreconstants.ProjectLabel]

	if err := rbac.AllowProjectScope(ctx, "region:networks:v2", identityapi.Delete, organizationID, projectID); err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	// The V2 API doesn't expose service principals, but they are mapped 1:1 to networks, so as the
	// real root of the tree we actually delete that and allow cascading deletion to do the
	// rest.
	return identity.New(c.client, c.namespace).Delete(ctx, organizationID, projectID, resource.Labels[constants.IdentityLabel])
}
