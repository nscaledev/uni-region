package agent

import (
	"context"
	"errors"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/filestorage/providers"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrInvalidProviderType = errors.New("invalid provider type")
)

type Provider struct {
	// client is Kubernetes client.
	client client.Client

	nats AgentInterface
}

var _ providers.Provider = &Provider{}

func New(ctx context.Context, cli client.Client, sc *unikornv1.FileStorageClass) (*Provider, error) {
	if sc == nil || sc.Spec.Provider == nil || sc.Spec.Provider.Agent == nil {
		return nil, ErrInvalidProviderType
	}
	if sc.Spec.Provider.Agent.Type != unikornv1.FileStorageAgentTypeNats {
		return nil, ErrInvalidProviderType
	}

	natsClient, err := NewNatsClient(ctx, sc.Spec.Provider.Agent.Nats)
	if err != nil {
		return nil, err
	}

	return &Provider{
		client: cli,
		nats:   natsClient,
	}, nil
}

func (p *Provider) CreateOrUpdateFileStorage(ctx context.Context, fs *unikornv1.FileStorage) error {
	remoteFileStorage, err := p.reconcileStorageVolume(ctx, fs)
	if err != nil {
		return err
	}

	if err := p.reconcileNetworkAttachments(ctx, fs, remoteFileStorage); err != nil {
		return err
	}

	// TODO: update fs.Status here.

	return nil
}

func (p *Provider) DeleteFileStorage(ctx context.Context, fs *unikornv1.FileStorage) error {
	// TODO: detach networks first (best-effort), then delete remote volume.
	return nil
}

func (p *Provider) reconcileStorageVolume(ctx context.Context, fs *unikornv1.FileStorage) (*RemoteFileStorage, error) {
	log := log.FromContext(ctx)

	projectID := fs.Labels[coreconstants.ProjectLabel]
	volumeID := fs.GetName()

	getReq := &GetFileStorage{
		ProjectId: projectID,
		VolumeId:  volumeID,
	}

	res, err := p.nats.GetFileStorage(ctx, getReq)
	if err == nil {
		log.V(1).Info("file storage already exists")

		return res, nil
	}

	log.V(1).Info("creating file storage")

	createReq := &CreateFileStorage{
		ProjectId:         projectID,
		VolumeId:          volumeID,
		Size:              fs.Spec.Size.Value(),
		RootSquashEnabled: fs.Spec.NFS.RootSquash,
	}

	res, err = p.nats.CreateFileStorage(ctx, createReq)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (p *Provider) reconcileNetworkAttachments(ctx context.Context, fs *unikornv1.FileStorage, remoteFileStorage *RemoteFileStorage) error {
	// Plan:
	// 1) Resolve networks referenced in fs.Spec.Attachments to concrete
	// 2) List remote attachments from p.nats
	// 3) Compute:
	//    - toCreate = desired - remote
	//    - toDelete = remote - desired
	// 4) Create missing, delete extraneous
	// 5) Consider idempotency and partial-failure retry semantics
	return nil
}
