/*
Copyright 2024-2025 the Unikorn Authors.
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

package driver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/unikorn-cloud/region/pkg/file-storage/provisioners/types"
)

const timeout = 30 * time.Second

var (
	ErrNoSuccess         = errors.New("nats: empty success response")
	ErrDriverConfig      = errors.New("nats: missing or invalid driver configuration")
	ErrInvalidAttachment = errors.New("invalid attachment")
)

const (
	SubjectKey          = "nats_subject"
	URLKey              = "nats_url"
	ClientSecretNameKey = "nats_client_secret_name" //nolint:gosec
)

type EmptyResponse struct{}

type CreateFileSystem struct {
	RemoteIdentifier  `json:",inline"`
	Size              int64 `json:"size"`
	RootSquashEnabled bool  `json:"rootSquashEnabled"`
}

type CreateFileSystemResponse struct {
	Path string `json:"path"`
}

type CreateMountTarget struct {
	RemoteIdentifier `json:",inline"`
	VlanID           int64  `json:"vlanId"`
	StartIP          string `json:"startIp"`
	EndIP            string `json:"endIp"`
	NetworkPrefix    string `json:"networkPrefix"`
}

type DeleteFileSystem struct {
	RemoteIdentifier `json:",inline"`
	Force            bool `json:"force"`
}

type DeleteMountTarget struct {
	RemoteIdentifier `json:",inline"`
	VlanID           int64 `json:"vlanId"`
}

type GetFileSystem struct {
	RemoteIdentifier `json:",inline"`
}

type GetFileSystemResponse struct {
	Size              int64  `json:"size"`
	Path              string `json:"path"`
	RootSquashEnabled bool   `json:"rootSquashEnabled"`
	UsedCapacity      int64  `json:"usedCapacity"`
}

type ListFileSystemMountTargets struct {
	RemoteIdentifier `json:",inline"`
}

type ListFileSystemMountTargetsResponse struct {
	Items []Attachment `json:"items"`
}

type Attachment struct {
	VlanID  int64  `json:"vlanId"`
	StartIP string `json:"startIp"`
	EndIP   string `json:"endIp"`
}

type Resize struct {
	RemoteIdentifier `json:",inline"`
	Size             int64 `json:"size"`
}

type ResizeResponse struct {
	Size         int64 `json:"size"`
	UsedCapacity int64 `json:"usedCapacity"`
}

type UpdateRootSquash struct {
	RemoteIdentifier  `json:",inline"`
	RootSquashEnabled bool `json:"rootSquashEnabled"`
}

type NatsResponseEnvelope[T any] struct {
	Error   *ResponseError `json:"error,omitempty"`
	Success *T             `json:"success,omitempty"`
}

type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type RemoteIdentifier struct {
	ProjectID string `json:"projectId"`
	VolumeID  string `json:"volumeId"`
}

// doRequest wraps the common NATS request/response pattern and unmarshals into a typed envelope.
func doRequest[T any](ctx context.Context, nc *nats.Conn, subject string, req any) (*T, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
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

	if env.Error != nil {
		return nil, remoteErrorFromEnvelope(env.Error)
	}

	if env.Success == nil {
		return nil, ErrNoSuccess
	}

	return env.Success, nil
}

// remoteErrorFromEnvelope maps structured remote errors to local typed errors.
func remoteErrorFromEnvelope(errResp *ResponseError) error {
	switch errResp.Code {
	case "invalid_request":
		return fmt.Errorf("%w: %s", types.ErrInvalidRequest, errResp.Message)
	case "not_found":
		return fmt.Errorf("%w: %s", types.ErrNotFound, errResp.Message)
	default:
		return fmt.Errorf("%w: %s: %s", types.ErrRemoteError, errResp.Code, errResp.Message)
	}
}
