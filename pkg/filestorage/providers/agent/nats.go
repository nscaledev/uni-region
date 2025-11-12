package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
)

const timeout = 30 * time.Second

var ErrNoSuccess = errors.New("nats: empty success response")

type NatsClient struct {
	client  *nats.Conn
	options *unikornv1.FileStorageProviderAgentNatsSpec
}

var _ AgentInterface = &NatsClient{}

func NewNatsClient(ctx context.Context, options *unikornv1.FileStorageProviderAgentNatsSpec) (*NatsClient, error) {
	nc, err := connectToNATS(options.NatsConnectionSpec)
	if err != nil {
		return nil, err
	}

	return &NatsClient{
		client:  nc,
		options: options,
	}, nil
}

func connectToNATS(_ unikornv1.NatsConnectionSpec) (*nats.Conn, error) {
	// TODO: implement the real thing
	return nats.Connect(nats.DefaultURL)
}

func (c *NatsClient) CreateFileStorage(ctx context.Context, req *CreateFileStorage) (*RemoteFileStorage, error) {
	return doRequest[RemoteFileStorage](ctx, c.client, c.subject("create"), "create", req)
}

func (c *NatsClient) GetFileStorage(ctx context.Context, req *GetFileStorage) (*RemoteFileStorage, error) {
	return doRequest[RemoteFileStorage](ctx, c.client, c.subject("get"), "get", req)
}

// AttachToNetwork
// ListNetworkAttachments
// DetachFromNetwork

// subject composes the base subject with the given suffix, ensuring a single dot separator.
func (c *NatsClient) subject(suffix string) string {
	base := strings.TrimSuffix(c.options.Subject, ".")
	if base == "" {
		return suffix
	}
	return base + "." + suffix
}

// doRequest wraps the common NATS request/response pattern and unmarshals into a typed envelope.
func doRequest[T any](ctx context.Context, nc *nats.Conn, subject string, action string, req any) (*T, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal %q request: %w", action, err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	msg, err := nc.RequestWithContext(ctx, subject, payload)
	if err != nil {
		// NATS returns an error here only for transport-level failures:
		// - disconnected/unavailable connection
		// - request timeout
		// - no subscribers for the subject
		// Application-level errors from the agent are returned in the response envelope and handled below.
		return nil, fmt.Errorf("nats request %q: %w", subject, err)
	}

	var env NatsResponseEnvelope[T]
	if err := json.Unmarshal(msg.Data, &env); err != nil {
		return nil, fmt.Errorf("decode %q response: %w", subject, err)
	}
	if env.Error != "" {
		return nil, fmt.Errorf("remote error %q: %s", subject, env.Error)
	}
	if env.Success == nil {
		return nil, ErrNoSuccess
	}
	return env.Success, nil
}
