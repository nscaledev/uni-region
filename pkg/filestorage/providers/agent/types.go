package agent

import (
	"context"
)

type AgentInterface interface {
	CreateFileStorage(ctx context.Context, req *CreateFileStorage) (*RemoteFileStorage, error)
	GetFileStorage(ctx context.Context, req *GetFileStorage) (*RemoteFileStorage, error)
	//AttachToNetwork
	//...
}

type RemoteFileStorage struct {
	Id                string `json:"id"`
	Size              int64  `json:"size"`
	Path              string `json:"path"`
	RootSquashEnabled bool   `json:"rootSquashEnabled"`
	UsedCapacity      int64  `json:"usedCapacity"`
}

type CreateFileStorage struct {
	ProjectId         string `json:"projectId"`
	VolumeId          string `json:"volumeId"`
	Size              int64  `json:"size"`
	RootSquashEnabled bool   `json:"rootSquashEnabled"`
}

type GetFileStorage struct {
	ProjectId string `json:"projectId"`
	VolumeId  string `json:"volumeId"`
}

type NatsResponseEnvelope[T any] struct {
	Error   string `json:"error,omitempty"`
	Success *T     `json:"success,omitempty"`
}
