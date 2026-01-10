/*
Copyright 2025 the Unikorn Authors.
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

package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spjmurray/go-util/pkg/set"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrUnimplmented is raised when something isn't done, nor makes zero senese.
	ErrUnimplmented = errors.New("interface unimplemnted")

	// ErrResource is raised when a resource is in a bad state.
	ErrResource = errors.New("resource error")
)

const (
	NodeClassLabel = "kubernetes.region.unikorn-cloud.org/node-class"
)

type Provider struct {
	// client is Kubernetes client.
	client client.Client

	// region is the current region configuration.
	region *unikornv1.Region
}

var _ types.Provider = &Provider{}

func New(ctx context.Context, cli client.Client, region *unikornv1.Region) (*Provider, error) {
	p := &Provider{
		client: cli,
		region: region,
	}

	return p, nil
}

// Region returns the provider's region.
func (p *Provider) Region(ctx context.Context) (*unikornv1.Region, error) {
	// TODO: atomic refresh.
	return p.region, nil
}

// ClientFromConfigBytes is a utility function to get a client for a kubeconfig.
func ClientFromConfigBytes(kubeconfig []byte) (client.Client, error) {
	config, err := clientcmd.NewClientConfigFromBytes(kubeconfig)
	if err != nil {
		return nil, err
	}

	rawConfig, err := config.RawConfig()
	if err != nil {
		return nil, err
	}

	getter := func() (*clientcmdapi.Config, error) {
		return &rawConfig, nil
	}

	restConfig, err := clientcmd.BuildConfigFromKubeconfigGetter("", getter)
	if err != nil {
		return nil, err
	}

	client, err := client.New(restConfig, client.Options{})
	if err != nil {
		return nil, err
	}

	return client, nil
}

func ListSchedulableNodes(ctx context.Context, cli client.Client) (*corev1.NodeList, error) {
	req, err := labels.NewRequirement(NodeClassLabel, selection.Exists, nil)
	if err != nil {
		return nil, err
	}

	options := &client.ListOptions{
		LabelSelector: labels.NewSelector().Add(*req),
	}

	nodes := &corev1.NodeList{}

	if err := cli.List(ctx, nodes, options); err != nil {
		return nil, err
	}

	return nodes, nil
}

// regionClient grabs a client to the region's Kubernetes cluster.
func (p *Provider) regionClient(ctx context.Context) (client.Client, error) {
	secret := &corev1.Secret{}

	if err := p.client.Get(ctx, client.ObjectKey{Namespace: p.region.Namespace, Name: p.region.Spec.Kubernetes.KubeconfigSecret.Name}, secret); err != nil {
		return nil, err
	}

	kubeconfig, ok := secret.Data["kubeconfig"]
	if !ok {
		return nil, fmt.Errorf("%w: kubeconfig kye missing in region secret", ErrResource)
	}

	client, err := ClientFromConfigBytes(kubeconfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Flavors list all available flavors.
func (p *Provider) Flavors(ctx context.Context) (types.FlavorList, error) {
	client, err := p.regionClient(ctx)
	if err != nil {
		return nil, err
	}

	nodes, err := ListSchedulableNodes(ctx, client)
	if err != nil {
		return nil, err
	}

	classes := set.New[string]()

	for i := range nodes.Items {
		classes.Add(nodes.Items[i].Labels[NodeClassLabel])
	}

	flavors := make(types.FlavorList, 0, len(p.region.Spec.Kubernetes.Nodes))

	// TODO: we *should* be able to auto-discover a lot of what's required from
	// the node information, however things like the allocatable memory in the status
	// isn't necessarily a nice round number for example.
	for _, node := range p.region.Spec.Kubernetes.Nodes {
		if !classes.Contains(node.ID) {
			continue
		}

		flavor := types.Flavor{
			ID:           node.ID,
			Name:         node.Name,
			CPUs:         *node.CPU.Count,
			Memory:       node.Memory,
			Disk:         node.Disk,
			Architecture: types.X86_64,
		}

		if node.GPU != nil {
			flavor.GPU = &types.GPU{
				Vendor:        types.GPUVendor(node.GPU.Vendor),
				Model:         node.GPU.Model,
				Memory:        node.GPU.Memory,
				PhysicalCount: node.GPU.PhysicalCount,
				LogicalCount:  node.GPU.LogicalCount,
			}
		}

		flavors = append(flavors, flavor)
	}

	return flavors, nil
}

// ListImages lists all available images.
func (p *Provider) ListImages(ctx context.Context, organizationID string) (types.ImageList, error) {
	return nil, ErrUnimplmented
}

// GetImage retrieves a specific image by its ID.
func (p *Provider) GetImage(ctx context.Context, organizationID, imageID string) (*types.Image, error) {
	return nil, ErrUnimplmented
}

// CreateImage creates a new image.
func (p *Provider) CreateImage(ctx context.Context, image *types.Image, url string) (*types.Image, error) {
	return nil, ErrUnimplmented
}

// UploadImage uploads data to an image.
func (p *Provider) UploadImageData(ctx context.Context, imageID string, reader io.Reader) error {
	return ErrUnimplmented
}

// DeleteImage deletes an image.
func (p *Provider) DeleteImage(ctx context.Context, imageID string) error {
	return ErrUnimplmented
}

// CreateIdentity creates a new identity for cloud infrastructure.
func (p *Provider) CreateIdentity(ctx context.Context, identity *unikornv1.Identity) error {
	return ErrUnimplmented
}

// DeleteIdentity cleans up an identity for cloud infrastructure.
func (p *Provider) DeleteIdentity(ctx context.Context, identity *unikornv1.Identity) error {
	return ErrUnimplmented
}

// CreateNetwork creates a new physical network.
func (p *Provider) CreateNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error {
	return ErrUnimplmented
}

// DeleteNetwork deletes a physical network.
func (p *Provider) DeleteNetwork(ctx context.Context, identity *unikornv1.Identity, network *unikornv1.Network) error {
	return ErrUnimplmented
}

// ListExternalNetworks returns a list of external networks if the platform
// supports such a concept.
func (p *Provider) ListExternalNetworks(ctx context.Context) (types.ExternalNetworks, error) {
	return nil, ErrUnimplmented
}

// CreateSecurityGroup creates a new security group.
func (p *Provider) CreateSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error {
	return ErrUnimplmented
}

// DeleteSecurityGroup deletes a security group.
func (p *Provider) DeleteSecurityGroup(ctx context.Context, identity *unikornv1.Identity, securityGroup *unikornv1.SecurityGroup) error {
	return ErrUnimplmented
}

// CreateServer creates a new server.
func (p *Provider) CreateServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	return ErrUnimplmented
}

// RebootServer reboots a server.
func (p *Provider) RebootServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, hard bool) error {
	return ErrUnimplmented
}

// StartServer starts a server.
func (p *Provider) StartServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	return ErrUnimplmented
}

// StopServer stops a server.
func (p *Provider) StopServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	return ErrUnimplmented
}

// DeleteServer deletes a server.
func (p *Provider) DeleteServer(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	return ErrUnimplmented
}

// UpdateServerState checks a server's state and modifies the resource in place.
func (p *Provider) UpdateServerState(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) error {
	return ErrUnimplmented
}

// CreateConsoleSession creates a new console session for a server.
func (p *Provider) CreateConsoleSession(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server) (string, error) {
	return "", ErrUnimplmented
}

// GetConsoleOutput retrieves the console output for a server.
func (p *Provider) GetConsoleOutput(ctx context.Context, identity *unikornv1.Identity, server *unikornv1.Server, length *int) (string, error) {
	return "", ErrUnimplmented
}
