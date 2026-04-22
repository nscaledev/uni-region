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

package loadbalancer

import (
	"cmp"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net"
	"slices"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/saga"
	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	identitycommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	handlercommon "github.com/unikorn-cloud/region/pkg/handler/common"
	"github.com/unikorn-cloud/region/pkg/handler/network"
	handlerutil "github.com/unikorn-cloud/region/pkg/handler/util"
	"github.com/unikorn-cloud/region/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	endpoint = "region:loadbalancers:v2"

	defaultHealthCheckIntervalSeconds    = 10
	defaultHealthCheckTimeoutSeconds     = 5
	defaultHealthCheckHealthyThreshold   = 2
	defaultHealthCheckUnhealthyThreshold = 2
)

var errNetworkPrefixMissing = stderrors.New("selected network has no prefix")

type Client struct {
	handlercommon.ClientArgs
}

func New(clientArgs handlercommon.ClientArgs) *Client {
	return &Client{
		ClientArgs: clientArgs,
	}
}

func convertIPv4Address(in *unikornv1core.IPv4Address) *openapi.Ipv4Address {
	if in == nil {
		return nil
	}

	out := in.String()

	return &out
}

func convertAllowedCIDRsV2(in []unikornv1core.IPv4Prefix) *[]string {
	if len(in) == 0 {
		return nil
	}

	out := make([]string, len(in))

	for i := range in {
		out[i] = in[i].String()
	}

	return &out
}

func convertHealthCheckV2(in *regionv1.LoadBalancerHealthCheck) *openapi.LoadBalancerHealthCheckV2 {
	if in == nil {
		return nil
	}

	return &openapi.LoadBalancerHealthCheckV2{
		IntervalSeconds:    ptr.To(in.IntervalSeconds),
		TimeoutSeconds:     ptr.To(in.TimeoutSeconds),
		HealthyThreshold:   ptr.To(in.HealthyThreshold),
		UnhealthyThreshold: ptr.To(in.UnhealthyThreshold),
	}
}

func convertMemberListV2(in []regionv1.LoadBalancerMember) []openapi.LoadBalancerMemberV2 {
	out := make([]openapi.LoadBalancerMemberV2, len(in))

	for i := range in {
		out[i] = openapi.LoadBalancerMemberV2{
			Address: in[i].Address.String(),
			Port:    in[i].Port,
		}
	}

	return out
}

func convertPoolV2(in *regionv1.LoadBalancerPool) openapi.LoadBalancerPoolV2 {
	return openapi.LoadBalancerPoolV2{
		ProxyProtocolV2: ptr.To(in.ProxyProtocolV2),
		Members:         convertMemberListV2(in.Members),
		HealthCheck:     convertHealthCheckV2(in.HealthCheck),
	}
}

func convertListenerListV2(in []regionv1.LoadBalancerListener) []openapi.LoadBalancerListenerV2 {
	out := make([]openapi.LoadBalancerListenerV2, len(in))

	for i := range in {
		out[i] = openapi.LoadBalancerListenerV2{
			AllowedCidrs:       convertAllowedCIDRsV2(in[i].AllowedCIDRs),
			IdleTimeoutSeconds: in[i].IdleTimeoutSeconds,
			Name:               in[i].Name,
			Pool:               convertPoolV2(&in[i].Pool),
			Port:               in[i].Port,
			Protocol:           openapi.LoadBalancerListenerProtocolV2(in[i].Protocol),
		}
	}

	return out
}

func convertV2(in *regionv1.LoadBalancer) *openapi.LoadBalancerV2Read {
	return &openapi.LoadBalancerV2Read{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.LoadBalancerV2Spec{
			PublicIP:  ptr.To(in.Spec.PublicIP),
			Listeners: convertListenerListV2(in.Spec.Listeners),
		},
		Status: openapi.LoadBalancerV2Status{
			RegionId:   in.Labels[constants.RegionLabel],
			NetworkId:  in.Labels[constants.NetworkLabel],
			VipAddress: convertIPv4Address(in.Status.VIPAddress),
			PublicIP:   convertIPv4Address(in.Status.PublicIP),
		},
	}
}

func convertV2List(in *regionv1.LoadBalancerList) openapi.LoadBalancersV2Read {
	out := make(openapi.LoadBalancersV2Read, len(in.Items))

	for i := range in.Items {
		out[i] = *convertV2(&in.Items[i])
	}

	return out
}

func (c *Client) ListV2(ctx context.Context, params openapi.GetApiV2LoadbalancersParams) (openapi.LoadBalancersV2Read, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.ResourceAPIVersionLabel: constants.MarshalAPIVersion(2),
	})

	var err error

	selector, err = rbac.AddOrganizationAndProjectIDQuery(ctx, selector, handlerutil.OrganizationIDQuery(params.OrganizationID), handlerutil.ProjectIDQuery(params.ProjectID))
	if err != nil {
		if rbac.HasNoMatches(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("%w: failed to add identity label selector", err)
	}

	selector, err = handlerutil.AddRegionIDQuery(selector, params.RegionID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to add region label selector", err)
	}

	selector, err = handlerutil.AddNetworkIDQuery(selector, params.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to add network label selector", err)
	}

	options := &client.ListOptions{
		Namespace:     c.Namespace,
		LabelSelector: selector,
	}

	result := &regionv1.LoadBalancerList{}

	if err := c.Client.List(ctx, result, options); err != nil {
		return nil, fmt.Errorf("%w: unable to list load balancers", err)
	}

	tagSelector, err := coreutil.DecodeTagSelectorParam(params.Tag)
	if err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource regionv1.LoadBalancer) bool {
		return !resource.Spec.Tags.ContainsAll(tagSelector) ||
			rbac.AllowProjectScope(ctx, endpoint, identityapi.Read, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]) != nil
	})

	slices.SortStableFunc(result.Items, func(a, b regionv1.LoadBalancer) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return convertV2List(result), nil
}

func (c *Client) GetV2Raw(ctx context.Context, loadBalancerID string) (*regionv1.LoadBalancer, error) {
	result := &regionv1.LoadBalancer{}

	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: c.Namespace, Name: loadBalancerID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: unable to lookup load balancer", err)
	}

	if err := rbac.AllowProjectScope(ctx, endpoint, identityapi.Read, result.Labels[coreconstants.OrganizationLabel], result.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	v, ok := result.Labels[constants.ResourceAPIVersionLabel]
	if !ok {
		return nil, errors.HTTPNotFound()
	}

	version, err := constants.UnmarshalAPIVersion(v)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to parse API version", err)
	}

	if version != 2 {
		return nil, errors.HTTPNotFound()
	}

	return result, nil
}

func (c *Client) GetV2(ctx context.Context, loadBalancerID string) (*openapi.LoadBalancerV2Read, error) {
	result, err := c.GetV2Raw(ctx, loadBalancerID)
	if err != nil {
		return nil, err
	}

	return convertV2(result), nil
}

func convertCreateToUpdateRequest(in *openapi.LoadBalancerV2Create) (*openapi.LoadBalancerV2Update, error) {
	t, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal request", err)
	}

	out := &openapi.LoadBalancerV2Update{}

	if err := json.Unmarshal(t, out); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal request", err)
	}

	return out, nil
}

func validatePort(port int, field string) error {
	if port < 1 || port > 65535 {
		return errors.HTTPUnprocessableContent(fmt.Sprintf("%s must be between 1 and 65535", field))
	}

	return nil
}

func validatePositiveInt(value *int, field string) error {
	if value != nil && *value < 1 {
		return errors.HTTPUnprocessableContent(fmt.Sprintf("%s must be greater than zero", field))
	}

	return nil
}

func validateListenerName(name string) error {
	if errs := validation.IsDNS1123Label(name); len(errs) != 0 {
		return errors.HTTPUnprocessableContent("listener name must be a valid DNS label")
	}

	if len(name) == 0 || name[0] < 'a' || name[0] > 'z' {
		return errors.HTTPUnprocessableContent("listener name must start with a lower-case letter")
	}

	return nil
}

func validatePoolMembersV2(members []openapi.LoadBalancerMemberV2) error {
	seen := map[string]struct{}{}

	for i := range members {
		if err := validatePort(members[i].Port, "member port"); err != nil {
			return err
		}

		key := fmt.Sprintf("%s/%d", members[i].Address, members[i].Port)

		if _, ok := seen[key]; ok {
			return errors.HTTPUnprocessableContent("pool members must be unique by address and port")
		}

		seen[key] = struct{}{}
	}

	return nil
}

func validateListenerProtocolV2(in *openapi.LoadBalancerListenerV2) error {
	if in.Protocol != openapi.LoadBalancerListenerProtocolV2Tcp && in.Protocol != openapi.LoadBalancerListenerProtocolV2Udp {
		return errors.HTTPUnprocessableContent("listener protocol must be tcp or udp")
	}

	if in.Protocol != openapi.LoadBalancerListenerProtocolV2Udp {
		return nil
	}

	if in.IdleTimeoutSeconds != nil {
		return errors.HTTPUnprocessableContent("idleTimeoutSeconds is only supported for TCP listeners")
	}

	if in.Pool.ProxyProtocolV2 != nil && *in.Pool.ProxyProtocolV2 {
		return errors.HTTPUnprocessableContent("proxyProtocolV2 is only supported for TCP listeners")
	}

	return nil
}

func validateListenerV2(in *openapi.LoadBalancerListenerV2) error {
	if err := validateListenerName(in.Name); err != nil {
		return err
	}

	if err := validatePort(in.Port, "listener port"); err != nil {
		return err
	}

	if err := validatePositiveInt(in.IdleTimeoutSeconds, "idleTimeoutSeconds"); err != nil {
		return err
	}

	if err := validatePoolMembersV2(in.Pool.Members); err != nil {
		return err
	}

	return validateListenerProtocolV2(in)
}

func validateListenersV2(in []openapi.LoadBalancerListenerV2) error {
	names := map[string]struct{}{}
	endpoints := map[string]struct{}{}

	for i := range in {
		if err := validateListenerV2(&in[i]); err != nil {
			return err
		}

		name := in[i].Name

		if _, ok := names[name]; ok {
			return errors.HTTPUnprocessableContent("listener names must be unique")
		}

		names[name] = struct{}{}

		key := fmt.Sprintf("%s/%d", in[i].Protocol, in[i].Port)

		if _, ok := endpoints[key]; ok {
			return errors.HTTPUnprocessableContent("listener protocol and port combinations must be unique")
		}

		endpoints[key] = struct{}{}
	}

	return nil
}

func parseIPv4Address(in, field string) (net.IP, error) {
	ip := net.ParseIP(in)
	if ip == nil || ip.To4() == nil {
		return nil, errors.OAuth2InvalidRequest(fmt.Sprintf("%s must be a valid IPv4 address", field))
	}

	return ip.To4(), nil
}

func parseIPv4Prefix(in, field string) (*net.IPNet, error) {
	ip, prefix, err := net.ParseCIDR(in)
	if err != nil || ip.To4() == nil {
		return nil, errors.OAuth2InvalidRequest(fmt.Sprintf("%s must contain valid IPv4 CIDR prefixes", field))
	}

	return prefix, nil
}

func generateRequestedVIPAddress(in *openapi.Ipv4Address) (unikornv1core.IPv4Address, bool, error) {
	if in == nil {
		return unikornv1core.IPv4Address{}, false, nil
	}

	ip, err := parseIPv4Address(*in, "vipAddress")
	if err != nil {
		return unikornv1core.IPv4Address{}, false, err
	}

	return unikornv1core.IPv4Address{IP: ip}, true, nil
}

func validateRequestedVIPAddressMatchesNetwork(vipAddress *unikornv1core.IPv4Address, network *regionv1.Network) error {
	if vipAddress == nil {
		return nil
	}

	if network.Spec.Prefix == nil {
		return fmt.Errorf("%w: %q", errNetworkPrefixMissing, network.Name)
	}

	if !network.Spec.Prefix.Contains(vipAddress.IP) {
		return errors.HTTPUnprocessableContent("vipAddress must be within the selected network CIDR")
	}

	return nil
}

func generateAllowedCIDRsV2(in *[]string) ([]unikornv1core.IPv4Prefix, error) {
	if in == nil || len(*in) == 0 {
		return nil, nil
	}

	out := make([]unikornv1core.IPv4Prefix, len(*in))

	for i := range *in {
		prefix, err := parseIPv4Prefix((*in)[i], "allowedCidrs")
		if err != nil {
			return nil, err
		}

		out[i] = unikornv1core.IPv4Prefix{
			IPNet: *prefix,
		}
	}

	return out, nil
}

func defaultPositiveInt(in *int, defaultValue int, field string) (int, error) {
	if in == nil {
		return defaultValue, nil
	}

	if *in < 1 {
		return 0, errors.HTTPUnprocessableContent(fmt.Sprintf("%s must be greater than zero", field))
	}

	return *in, nil
}

func generateHealthCheckV2(in *openapi.LoadBalancerHealthCheckV2) (regionv1.LoadBalancerHealthCheck, bool, error) {
	if in == nil {
		return regionv1.LoadBalancerHealthCheck{}, false, nil
	}

	intervalSeconds, err := defaultPositiveInt(in.IntervalSeconds, defaultHealthCheckIntervalSeconds, "intervalSeconds")
	if err != nil {
		return regionv1.LoadBalancerHealthCheck{}, false, err
	}

	timeoutSeconds, err := defaultPositiveInt(in.TimeoutSeconds, defaultHealthCheckTimeoutSeconds, "timeoutSeconds")
	if err != nil {
		return regionv1.LoadBalancerHealthCheck{}, false, err
	}

	healthyThreshold, err := defaultPositiveInt(in.HealthyThreshold, defaultHealthCheckHealthyThreshold, "healthyThreshold")
	if err != nil {
		return regionv1.LoadBalancerHealthCheck{}, false, err
	}

	unhealthyThreshold, err := defaultPositiveInt(in.UnhealthyThreshold, defaultHealthCheckUnhealthyThreshold, "unhealthyThreshold")
	if err != nil {
		return regionv1.LoadBalancerHealthCheck{}, false, err
	}

	if timeoutSeconds >= intervalSeconds {
		return regionv1.LoadBalancerHealthCheck{}, false, errors.HTTPUnprocessableContent("timeoutSeconds must be less than intervalSeconds")
	}

	return regionv1.LoadBalancerHealthCheck{
		IntervalSeconds:    intervalSeconds,
		TimeoutSeconds:     timeoutSeconds,
		HealthyThreshold:   healthyThreshold,
		UnhealthyThreshold: unhealthyThreshold,
	}, true, nil
}

func generateMemberListV2(in []openapi.LoadBalancerMemberV2) ([]regionv1.LoadBalancerMember, error) {
	out := make([]regionv1.LoadBalancerMember, len(in))

	for i := range in {
		ip, err := parseIPv4Address(in[i].Address, "member address")
		if err != nil {
			return nil, err
		}

		out[i] = regionv1.LoadBalancerMember{
			Address: unikornv1core.IPv4Address{IP: ip},
			Port:    in[i].Port,
		}
	}

	return out, nil
}

func generatePoolV2(in *openapi.LoadBalancerPoolV2) (*regionv1.LoadBalancerPool, error) {
	members, err := generateMemberListV2(in.Members)
	if err != nil {
		return nil, err
	}

	healthCheck, ok, err := generateHealthCheckV2(in.HealthCheck)
	if err != nil {
		return nil, err
	}

	var healthCheckPtr *regionv1.LoadBalancerHealthCheck
	if ok {
		healthCheckPtr = &healthCheck
	}

	return &regionv1.LoadBalancerPool{
		ProxyProtocolV2: in.ProxyProtocolV2 != nil && *in.ProxyProtocolV2,
		Members:         members,
		HealthCheck:     healthCheckPtr,
	}, nil
}

func generateListenerListV2(in []openapi.LoadBalancerListenerV2) ([]regionv1.LoadBalancerListener, error) {
	if err := validateListenersV2(in); err != nil {
		return nil, err
	}

	out := make([]regionv1.LoadBalancerListener, len(in))

	for i := range in {
		allowedCIDRs, err := generateAllowedCIDRsV2(in[i].AllowedCidrs)
		if err != nil {
			return nil, err
		}

		pool, err := generatePoolV2(&in[i].Pool)
		if err != nil {
			return nil, err
		}

		out[i] = regionv1.LoadBalancerListener{
			Name:               in[i].Name,
			Protocol:           regionv1.LoadBalancerListenerProtocol(in[i].Protocol),
			Port:               in[i].Port,
			AllowedCIDRs:       allowedCIDRs,
			IdleTimeoutSeconds: in[i].IdleTimeoutSeconds,
			Pool:               *pool,
		}
	}

	return out, nil
}

func (c *Client) generateV2(ctx context.Context, organizationID, projectID string, request *openapi.LoadBalancerV2Update, network *regionv1.Network, requestedVIPAddress *unikornv1core.IPv4Address) (*regionv1.LoadBalancer, error) {
	listeners, err := generateListenerListV2(request.Spec.Listeners)
	if err != nil {
		return nil, err
	}

	out := &regionv1.LoadBalancer{
		ObjectMeta: conversion.NewObjectMetadata(&request.Metadata, c.Namespace).
			WithOrganization(organizationID).
			WithProject(projectID).
			WithLabel(constants.RegionLabel, network.Labels[constants.RegionLabel]).
			WithLabel(constants.IdentityLabel, network.Labels[constants.IdentityLabel]).
			WithLabel(constants.NetworkLabel, network.Name).
			WithLabel(constants.ResourceAPIVersionLabel, constants.MarshalAPIVersion(2)).
			Get(),
		Spec: regionv1.LoadBalancerSpec{
			Tags:                conversion.GenerateTagList(request.Metadata.Tags),
			RequestedVIPAddress: requestedVIPAddress,
			PublicIP:            request.Spec.PublicIP != nil && *request.Spec.PublicIP,
			Listeners:           listeners,
		},
	}

	if err := handlerutil.InjectUserPrincipal(ctx, organizationID, projectID); err != nil {
		return nil, fmt.Errorf("%w: unable to set principal information", err)
	}

	if err := identitycommon.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	if err := controllerutil.SetOwnerReference(network, out, c.Client.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
		return nil, fmt.Errorf("%w: unable to set resource owner", err)
	}

	return out, nil
}

func allocationRequirements(publicIP bool) identityapi.ResourceAllocationList {
	out := identityapi.ResourceAllocationList{
		{
			Kind:      "loadbalancers",
			Committed: 1,
			Reserved:  0,
		},
	}

	if publicIP {
		out = append(out, identityapi.ResourceAllocation{
			Kind:      "publicips",
			Committed: 1,
			Reserved:  0,
		})
	}

	return out
}

func validateUpdateImmutability(current, required *regionv1.LoadBalancer) error {
	currentListeners := map[string]regionv1.LoadBalancerListener{}

	for i := range current.Spec.Listeners {
		currentListeners[current.Spec.Listeners[i].Name] = current.Spec.Listeners[i]
	}

	for i := range required.Spec.Listeners {
		currentListener, ok := currentListeners[required.Spec.Listeners[i].Name]
		if !ok {
			continue
		}

		if currentListener.Protocol != required.Spec.Listeners[i].Protocol {
			return errors.HTTPUnprocessableContent("listener protocol cannot be changed for an existing listener name")
		}

		if currentListener.Port != required.Spec.Listeners[i].Port {
			return errors.HTTPUnprocessableContent("listener port cannot be changed for an existing listener name")
		}
	}

	return nil
}

type createSaga struct {
	client *Client

	request             *openapi.LoadBalancerV2Update
	network             *regionv1.Network
	requestedVIPAddress *unikornv1core.IPv4Address

	loadBalancer *regionv1.LoadBalancer
}

func newCreateSaga(client *Client, request *openapi.LoadBalancerV2Update, network *regionv1.Network, requestedVIPAddress *unikornv1core.IPv4Address) *createSaga {
	return &createSaga{
		client:              client,
		request:             request,
		network:             network,
		requestedVIPAddress: requestedVIPAddress,
	}
}

func (s *createSaga) generate(ctx context.Context) error {
	resource, err := s.client.generateV2(ctx, s.network.Labels[coreconstants.OrganizationLabel], s.network.Labels[coreconstants.ProjectLabel], s.request, s.network, s.requestedVIPAddress)
	if err != nil {
		return err
	}

	s.loadBalancer = resource

	return nil
}

func (s *createSaga) createAllocation(ctx context.Context) error {
	if err := identityclient.NewAllocations(s.client.Client, s.client.Identity).Create(ctx, s.loadBalancer, allocationRequirements(s.loadBalancer.Spec.PublicIP)); err != nil {
		return err
	}

	return nil
}

func (s *createSaga) deleteAllocation(ctx context.Context) error {
	if err := identityclient.NewAllocations(s.client.Client, s.client.Identity).Delete(ctx, s.loadBalancer); err != nil {
		return err
	}

	return nil
}

func (s *createSaga) createLoadBalancer(ctx context.Context) error {
	if err := s.client.Client.Create(ctx, s.loadBalancer); err != nil {
		return fmt.Errorf("%w: unable to create load balancer", err)
	}

	return nil
}

func (s *createSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("generate load balancer", s.generate, nil),
		saga.NewAction("create quota allocation", s.createAllocation, s.deleteAllocation),
		saga.NewAction("create load balancer", s.createLoadBalancer, nil),
	}
}

func (c *Client) CreateV2(ctx context.Context, request *openapi.LoadBalancerV2Create) (*openapi.LoadBalancerV2Read, error) {
	networkResource, err := network.New(c.ClientArgs).GetV2Raw(ctx, request.Spec.NetworkId)
	if err != nil {
		return nil, err
	}

	organizationID := networkResource.Labels[coreconstants.OrganizationLabel]
	projectID := networkResource.Labels[coreconstants.ProjectLabel]

	if err := rbac.AllowProjectScopeCreate(ctx, c.Identity, endpoint, identityapi.Create, organizationID, projectID); err != nil {
		return nil, err
	}

	requestedVIPAddress, ok, err := generateRequestedVIPAddress(request.Spec.VipAddress)
	if err != nil {
		return nil, err
	}

	var requestedVIPAddressPtr *unikornv1core.IPv4Address
	if ok {
		requestedVIPAddressPtr = &requestedVIPAddress
	}

	if err := validateRequestedVIPAddressMatchesNetwork(requestedVIPAddressPtr, networkResource); err != nil {
		return nil, err
	}

	updateRequest, err := convertCreateToUpdateRequest(request)
	if err != nil {
		return nil, err
	}

	s := newCreateSaga(c, updateRequest, networkResource, requestedVIPAddressPtr)

	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return convertV2(s.loadBalancer), nil
}

type updateSaga struct {
	client *Client

	current *regionv1.LoadBalancer
	network *regionv1.Network
	request *openapi.LoadBalancerV2Update

	updated *regionv1.LoadBalancer
}

func newUpdateSaga(client *Client, current *regionv1.LoadBalancer, network *regionv1.Network, request *openapi.LoadBalancerV2Update) *updateSaga {
	return &updateSaga{
		client:  client,
		current: current,
		network: network,
		request: request,
	}
}

func (s *updateSaga) generate(ctx context.Context) error {
	required, err := s.client.generateV2(ctx, s.current.Labels[coreconstants.OrganizationLabel], s.current.Labels[coreconstants.ProjectLabel], s.request, s.network, s.current.Spec.RequestedVIPAddress)
	if err != nil {
		return err
	}

	if err := validateUpdateImmutability(s.current, required); err != nil {
		return err
	}

	if err := conversion.UpdateObjectMetadata(required, s.current, identitycommon.IdentityMetadataMutator); err != nil {
		return fmt.Errorf("%w: failed to merge metadata", err)
	}

	if v, ok := s.current.Annotations[coreconstants.AllocationAnnotation]; ok {
		required.Annotations[coreconstants.AllocationAnnotation] = v
	}

	s.updated = s.current.DeepCopy()
	s.updated.Labels = required.Labels
	s.updated.Annotations = required.Annotations
	s.updated.Spec = required.Spec

	return nil
}

func (s *updateSaga) updateAllocation(ctx context.Context) error {
	if err := identityclient.NewAllocations(s.client.Client, s.client.Identity).Update(ctx, s.current, allocationRequirements(s.updated.Spec.PublicIP)); err != nil {
		return err
	}

	return nil
}

func (s *updateSaga) revertAllocation(ctx context.Context) error {
	if err := identityclient.NewAllocations(s.client.Client, s.client.Identity).Update(ctx, s.current, allocationRequirements(s.current.Spec.PublicIP)); err != nil {
		return err
	}

	return nil
}

func (s *updateSaga) updateLoadBalancer(ctx context.Context) error {
	if err := s.client.Client.Patch(ctx, s.updated, client.MergeFromWithOptions(s.current, &client.MergeFromWithOptimisticLock{})); err != nil {
		if kerrors.IsConflict(err) {
			return errors.HTTPConflict().WithError(err)
		}

		return fmt.Errorf("%w: unable to update load balancer", err)
	}

	return nil
}

func (s *updateSaga) Actions() []saga.Action {
	return []saga.Action{
		saga.NewAction("generate load balancer", s.generate, nil),
		saga.NewAction("update quota allocation", s.updateAllocation, s.revertAllocation),
		saga.NewAction("update load balancer", s.updateLoadBalancer, nil),
	}
}

func (c *Client) UpdateV2(ctx context.Context, loadBalancerID string, request *openapi.LoadBalancerV2Update) (*openapi.LoadBalancerV2Read, error) {
	current, err := c.GetV2Raw(ctx, loadBalancerID)
	if err != nil {
		return nil, err
	}

	if err := rbac.AllowProjectScope(ctx, endpoint, identityapi.Update, current.Labels[coreconstants.OrganizationLabel], current.Labels[coreconstants.ProjectLabel]); err != nil {
		return nil, err
	}

	if current.DeletionTimestamp != nil {
		return nil, errors.HTTPUnprocessableContent("load balancer is being deleted")
	}

	networkResource, err := network.New(c.ClientArgs).GetV2Raw(ctx, current.Labels[constants.NetworkLabel])
	if err != nil {
		return nil, err
	}

	s := newUpdateSaga(c, current, networkResource, request)

	if err := saga.Run(ctx, s); err != nil {
		return nil, err
	}

	return convertV2(s.updated), nil
}

func (c *Client) DeleteV2(ctx context.Context, loadBalancerID string) error {
	resource, err := c.GetV2Raw(ctx, loadBalancerID)
	if err != nil {
		return err
	}

	if err := rbac.AllowProjectScope(ctx, endpoint, identityapi.Delete, resource.Labels[coreconstants.OrganizationLabel], resource.Labels[coreconstants.ProjectLabel]); err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return nil
	}

	if err := c.Client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: unable to delete load balancer", err)
	}

	return nil
}
