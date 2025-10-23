package storage

import (
	"context"

	"github.com/unikorn-cloud/core/pkg/server/errors"

	coreutil "github.com/unikorn-cloud/core/pkg/server/util"
	kerrors "k8s.io/apimachinery/pkg/api/errors"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/handler/util"

	"github.com/unikorn-cloud/region/pkg/client"
	"github.com/unikorn-cloud/region/pkg/openapi"
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

func (c *Client) Get(ctx context.Context, organizationID, projectID, serverID string) error {
	result, err := c.GetRaw(ctx, organizationID, projectID, networkID)
	if err != nil {
		return nil, err
	}

	return c.convert(ctx, result), nil
}

func (c *Client) Update(ctx context.Context, organizationID, projectID, identityID, serverID string, request *openapi.ServerWrite) error {
	return nil
}

func (c *Client) Reboot(ctx context.Context, organizationID, projectID, identityID, serverID string, hard bool) error {
	return nil
}

func (c *Client) Start(ctx context.Context, organizationID, projectID, identityID, serverID string) error {
	return nil
}

func (c *Client) Stop(ctx context.Context, organizationID, projectID, identityID, serverID string) error {
	return nil
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
