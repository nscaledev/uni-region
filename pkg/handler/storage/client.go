package storage

import (
	"context"

	"github.com/unikorn-cloud/core/pkg/server/errors"

	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	kerrors "k8s.io/apimachinery/pkg/api/errors"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/util"

	"github.com/unikorn-cloud/region/pkg/openapi"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client provides a restful API for identities.
type Client struct {
	// client ia a Kubernetes client.
	client client.Client
	// namespace we are running in.
	namespace string
}

// New creates a new client.
func NewClient(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

// GetRaw gives access to the raw Kubernetes resource.
func (c *Client) GetRaw(ctx context.Context, organizationID, projectID, networkID string) (*unikornv1.FileStorage, error) {
	resource := &unikornv1.FileStorage{}

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

func (c *Client) Get(ctx context.Context, organizationID, projectID, storageID string) (*openapi.NetworkRead, error) {
	result, err := c.GetRaw(ctx, organizationID, projectID, storageID)
	if err != nil {
		return nil, err
	}

	return c.convert(ctx, result), nil
}

// Create instantiates a new resource.
func (c *Client) Create(ctx context.Context, organizationID, projectID, identityID string, request *openapi.NetworkWrite) (*openapi.NetworkRead, error) {
	resource, err := c.generate(ctx, organizationID, projectID, identityID, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("unable to create storage").WithError(err)
	}

	return c.convert(ctx, resource), nil
}


func (c *Client) Delete(ctx context.Context, organizationID, projectID, storageID string) error {
	result, err := c.GetRaw(ctx, organizationID, projectID, storageID)
	if err != nil {
		return err
	}

	if err := c.client.Delete(ctx, result, util.ForegroundDeleteOptions()); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("unable to delete storage").WithError(err)
	}

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