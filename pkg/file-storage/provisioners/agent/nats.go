/*
Copyright 2024-2025 the Unikorn Authors.

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

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

const timeout = 30 * time.Second

var (
	ErrNoSuccess   = errors.New("nats: empty success response")
	ErrRemoteError = errors.New("nats: remote error")
)

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
}

type CreateMountTargetResponse struct{}

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

type NatsResponseEnvelope[T any] struct {
	Error   string `json:"error,omitempty"`
	Success *T     `json:"success,omitempty"`
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

	if env.Error != "" {
		return nil, fmt.Errorf("%w: remote error on %s: %s", ErrRemoteError, subject, env.Error)
	}

	if env.Success == nil {
		return nil, ErrNoSuccess
	}

	return env.Success, nil
}
