package storage

import (
	"context"

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

func (c *Client) Get(ctx context.Context, organizationID, projectID, serverID string) error {
	return nil
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

func (c *Client) Delete(ctx context.Context, organizationID, projectID, serverID string) error {
	return nil
}
