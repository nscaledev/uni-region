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

package simulated

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ErrUnsupportedOperation = fmt.Errorf("simulated provider operation unsupported")

type imagePredicate func(types.Image) bool

type imageQuery struct {
	images     func() []types.Image
	predicates []imagePredicate
}

func (q *imageQuery) AvailableToOrganization(organizationIDs ...string) types.ImageQuery {
	q.predicates = append(q.predicates, func(image types.Image) bool {
		return image.OrganizationID == nil || slices.Contains(organizationIDs, *image.OrganizationID)
	})

	return q
}

func (q *imageQuery) OwnedByOrganization(organizationIDs ...string) types.ImageQuery {
	q.predicates = append(q.predicates, func(image types.Image) bool {
		return image.OrganizationID != nil && slices.Contains(organizationIDs, *image.OrganizationID)
	})

	return q
}

func (q *imageQuery) StatusIn(statuses ...types.ImageStatus) types.ImageQuery {
	q.predicates = append(q.predicates, func(image types.Image) bool {
		return slices.Contains(statuses, image.Status)
	})

	return q
}

func (q *imageQuery) List(_ context.Context) (types.ImageList, error) {
	var result types.ImageList

images:
	for _, image := range q.images() {
		for _, predicate := range q.predicates {
			if !predicate(image) {
				continue images
			}
		}

		result = append(result, image)
	}

	return result, nil
}

type Provider struct {
	client client.Client
	region *unikornv1.Region

	lock         sync.RWMutex
	customImages map[string]types.Image
}

var _ types.Provider = &Provider{}

func New(_ context.Context, cli client.Client, region *unikornv1.Region) (*Provider, error) {
	return &Provider{
		client:       cli,
		region:       region,
		customImages: map[string]types.Image{},
	}, nil
}

func (p *Provider) Kind() unikornv1.Provider {
	return unikornv1.ProviderSimulated
}

func (p *Provider) Region(_ context.Context) (*unikornv1.Region, error) {
	return p.region, nil
}

func (p *Provider) Flavors(_ context.Context) (types.FlavorList, error) {
	cpuFamily := "Simulated CPU"
	defaultFlavorMemory := resource.MustParse("8Gi")
	defaultFlavorDisk := resource.MustParse("100Gi")
	gpuFlavorMemory := resource.MustParse("16Gi")
	gpuFlavorDisk := resource.MustParse("200Gi")
	gpuMemory := resource.MustParse("16Gi")

	return types.FlavorList{
		{
			ID:           "11111111-1111-1111-1111-111111111111",
			Name:         "sim-standard-4",
			Architecture: types.X86_64,
			CPUs:         4,
			CPUFamily:    &cpuFamily,
			Memory:       &defaultFlavorMemory,
			Disk:         &defaultFlavorDisk,
		},
		{
			ID:           "22222222-2222-2222-2222-222222222222",
			Name:         "sim-gpu-8",
			Architecture: types.X86_64,
			CPUs:         8,
			CPUFamily:    &cpuFamily,
			Memory:       &gpuFlavorMemory,
			Disk:         &gpuFlavorDisk,
			GPU: &types.GPU{
				Vendor:        types.Nvidia,
				Model:         "L4",
				Memory:        &gpuMemory,
				PhysicalCount: 1,
				LogicalCount:  1,
			},
		},
	}, nil
}

func (p *Provider) QueryImages() (types.ImageQuery, error) {
	return &imageQuery{
		images: p.listImages,
	}, nil
}

func (p *Provider) listImages() []types.Image {
	p.lock.RLock()
	defer p.lock.RUnlock()

	result := make([]types.Image, 0, len(p.customImages)+2)
	result = append(result, builtInImages()...)

	for _, image := range p.customImages {
		result = append(result, image)
	}

	slices.SortStableFunc(result, func(a, b types.Image) int {
		return stringsCompare(a.Name, b.Name)
	})

	return result
}

func stringsCompare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func builtInImages() []types.Image {
	now := time.Unix(1_742_000_000, 0).UTC()
	noble := "noble"

	return []types.Image{
		{
			ID:             "33333333-3333-3333-3333-333333333333",
			Name:           "ubuntu-24.04-amd64",
			Created:        now,
			Modified:       now,
			Architecture:   types.X86_64,
			SizeGiB:        20,
			Virtualization: types.Virtualized,
			OS: types.ImageOS{
				Kernel:   types.Linux,
				Family:   types.Debian,
				Distro:   types.Ubuntu,
				Codename: &noble,
				Version:  "24.04",
			},
			Packages: &types.ImagePackages{
				"kubernetes": "v1.31.0",
			},
			Status: types.ImageStatusReady,
		},
		{
			ID:             "44444444-4444-4444-4444-444444444444",
			Name:           "ubuntu-24.04-gpu-amd64",
			Created:        now,
			Modified:       now,
			Architecture:   types.X86_64,
			SizeGiB:        30,
			Virtualization: types.Virtualized,
			GPU: &types.ImageGPU{
				Vendor: types.Nvidia,
				Driver: "550.54.15",
				Models: []string{"L4"},
			},
			OS: types.ImageOS{
				Kernel:   types.Linux,
				Family:   types.Debian,
				Distro:   types.Ubuntu,
				Codename: &noble,
				Version:  "24.04",
			},
			Status: types.ImageStatusReady,
		},
	}
}

func (p *Provider) GetImage(_ context.Context, organizationID, imageID string) (*types.Image, error) {
	for _, image := range p.listImages() {
		if image.ID != imageID {
			continue
		}

		if image.OrganizationID != nil && *image.OrganizationID != organizationID {
			return nil, fmt.Errorf("%w: image %s", coreerrors.ErrResourceNotFound, imageID)
		}

		imageCopy := image

		return &imageCopy, nil
	}

	return nil, fmt.Errorf("%w: image %s", coreerrors.ErrResourceNotFound, imageID)
}

func (p *Provider) CreateImage(_ context.Context, image *types.Image, _ string) (*types.Image, error) {
	now := time.Now().UTC()
	created := *image
	created.ID = uuid.NewString()
	created.Created = now
	created.Modified = now
	created.Status = types.ImageStatusReady

	p.lock.Lock()
	defer p.lock.Unlock()
	p.customImages[created.ID] = created

	return &created, nil
}

func (p *Provider) DeleteImage(_ context.Context, imageID string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if _, ok := p.customImages[imageID]; !ok {
		return fmt.Errorf("%w: image %s", coreerrors.ErrResourceNotFound, imageID)
	}

	delete(p.customImages, imageID)

	return nil
}

func (p *Provider) ListExternalNetworks(_ context.Context) (types.ExternalNetworks, error) {
	return types.ExternalNetworks{
		{ID: "55555555-5555-5555-5555-555555555555", Name: "sim-public"},
		{ID: "66666666-6666-6666-6666-666666666666", Name: "sim-public-secondary"},
	}, nil
}

func unsupported(op string) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedOperation, op)
}

func (p *Provider) CreateIdentity(_ context.Context, _ *unikornv1.Identity) error {
	return nil
}

func (p *Provider) DeleteIdentity(_ context.Context, _ *unikornv1.Identity) error {
	return nil
}

func storageRange(prefix net.IPNet) *unikornv1.AttachmentIPRange {
	ba := big.NewInt(0).SetBytes(prefix.IP.To4())

	bs := big.NewInt(0).Add(ba, big.NewInt(16))
	be := big.NewInt(0).Add(ba, big.NewInt(127))

	return &unikornv1.AttachmentIPRange{
		Start: unikornv1core.IPv4Address{IP: net.IP(bs.Bytes())},
		End:   unikornv1core.IPv4Address{IP: net.IP(be.Bytes())},
	}
}

func (p *Provider) CreateNetwork(_ context.Context, _ *unikornv1.Identity, network *unikornv1.Network) error {
	network.Status.Openstack = &unikornv1.NetworkStatusOpenstack{
		NetworkID:    ptr(uuid.NewSHA1(uuid.NameSpaceURL, []byte("simulated-network/"+network.Name)).String()),
		SubnetID:     ptr(uuid.NewSHA1(uuid.NameSpaceURL, []byte("simulated-subnet/"+network.Name)).String()),
		StorageRange: storageRange(network.Spec.Prefix.IPNet),
	}

	return nil
}

func (p *Provider) DeleteNetwork(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Network) error {
	return nil
}

func (p *Provider) CreateSecurityGroup(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.SecurityGroup) error {
	return unsupported("CreateSecurityGroup")
}

func (p *Provider) DeleteSecurityGroup(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.SecurityGroup) error {
	return unsupported("DeleteSecurityGroup")
}

func (p *Provider) CreateServer(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server) error {
	return unsupported("CreateServer")
}

func (p *Provider) RebootServer(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server, _ bool) error {
	return unsupported("RebootServer")
}

func (p *Provider) StartServer(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server) error {
	return unsupported("StartServer")
}

func (p *Provider) StopServer(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server) error {
	return unsupported("StopServer")
}

func (p *Provider) DeleteServer(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server) error {
	return unsupported("DeleteServer")
}

func (p *Provider) UpdateServerState(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server) error {
	return unsupported("UpdateServerState")
}

func (p *Provider) CreateConsoleSession(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server) (string, error) {
	return "", unsupported("CreateConsoleSession")
}

func (p *Provider) GetConsoleOutput(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server, _ *int) (string, error) {
	return "", unsupported("GetConsoleOutput")
}

func (p *Provider) CreateSnapshot(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.Server, _ *types.Image) (*types.Image, error) {
	return nil, unsupported("CreateSnapshot")
}

func ptr[T any](v T) *T {
	return &v
}
