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
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"
	regionids "github.com/unikorn-cloud/region/pkg/ids"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ErrUnsupportedOperation = fmt.Errorf("simulated provider operation unsupported")

type imagePredicate func(types.Image) bool

type imageQuery struct {
	images     func() []types.Image
	predicates []imagePredicate
}

func (q *imageQuery) AvailableToOrganization(organizationIDs ...identityids.OrganizationID) types.ImageQuery {
	ids := types.OrganizationIDStrings(organizationIDs)

	q.predicates = append(q.predicates, func(image types.Image) bool {
		return image.OrganizationID == nil || slices.Contains(ids, *image.OrganizationID)
	})

	return q
}

func (q *imageQuery) OwnedByOrganization(organizationIDs ...identityids.OrganizationID) types.ImageQuery {
	ids := types.OrganizationIDStrings(organizationIDs)

	q.predicates = append(q.predicates, func(image types.Image) bool {
		return image.OrganizationID != nil && slices.Contains(ids, *image.OrganizationID)
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
	result := &cache.ListSnapshot[types.Image]{}

images:
	for _, image := range q.images() {
		for _, predicate := range q.predicates {
			if !predicate(image) {
				continue images
			}
		}

		result.Items = append(result.Items, &image)
	}

	return result, nil
}

type Provider struct {
	client client.Client
	region *unikornv1.Region

	lock             sync.RWMutex
	customImages     map[string]types.Image
	simulatedServers map[string]*simulatedServer
}

var _ types.Provider = &Provider{}

func New(_ context.Context, cli client.Client, region *unikornv1.Region) (*Provider, error) {
	return &Provider{
		client:           cli,
		region:           region,
		customImages:     map[string]types.Image{},
		simulatedServers: map[string]*simulatedServer{},
	}, nil
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

func (p *Provider) VolumeClasses(_ context.Context) (types.VolumeClassList, error) {
	return types.VolumeClassList{
		{
			ID:             "33333333-3333-3333-3333-333333333333",
			Name:           "sim-standard-volume",
			Description:    "Simulated SSD block storage",
			MinimumSizeGiB: ptr(int64(1)),
			MaximumSizeGiB: ptr(int64(16384)),
			Media:          types.VolumeClassMediaSSD,
		},
		{
			ID:             "44444444-4444-4444-4444-444444444444",
			Name:           "sim-fast-volume",
			Description:    "Simulated NVMe block storage",
			MinimumSizeGiB: ptr(int64(10)),
			MaximumSizeGiB: ptr(int64(2048)),
			Media:          types.VolumeClassMediaNVMe,
			Performance: &types.VolumeClassPerformance{
				MaxIOPS:       ptr(25000),
				MaxThroughput: ptr(500),
			},
			Encrypted: true,
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
				Family:   "debian",
				Distro:   "ubuntu",
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
				Family:   "debian",
				Distro:   "ubuntu",
				Codename: &noble,
				Version:  "24.04",
			},
			Status: types.ImageStatusReady,
		},
	}
}

func (p *Provider) GetImage(_ context.Context, organizationID identityids.OrganizationID, imageID regionids.ImageID) (*types.Image, error) {
	imageIDString := imageID.String()

	for _, image := range p.listImages() {
		if image.ID != imageIDString {
			continue
		}

		if image.OrganizationID != nil && *image.OrganizationID != organizationID.String() {
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

func (p *Provider) DeleteImage(_ context.Context, imageID regionids.ImageID) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	imageIDString := imageID.String()

	if _, ok := p.customImages[imageIDString]; !ok {
		return fmt.Errorf("%w: image %s", coreerrors.ErrResourceNotFound, imageID)
	}

	delete(p.customImages, imageIDString)

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
	return nil
}

func (p *Provider) DeleteSecurityGroup(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.SecurityGroup) error {
	return nil
}

func deterministicIPv4Address(prefix net.IPNet, seed string) (*unikornv1core.IPv4Address, error) {
	networkIP := prefix.IP.To4()
	if networkIP == nil {
		return nil, fmt.Errorf("%w: prefix %s is not IPv4", coreerrors.ErrConsistency, prefix.String())
	}

	ones, bits := prefix.Mask.Size()
	if bits != net.IPv4len*8 {
		return nil, fmt.Errorf("%w: prefix %s is not IPv4", coreerrors.ErrConsistency, prefix.String())
	}

	hostBits := bits - ones
	if hostBits < 2 {
		return nil, fmt.Errorf("%w: prefix %s has no usable host addresses", coreerrors.ErrConsistency, prefix.String())
	}

	usableHostCount := big.NewInt(1)
	usableHostCount.Lsh(usableHostCount, uint(hostBits))
	usableHostCount.Sub(usableHostCount, big.NewInt(2))

	hash := uuid.NewSHA1(uuid.NameSpaceURL, []byte(seed))
	offset := big.NewInt(0).SetBytes(hash[:])
	offset.Mod(offset, usableHostCount)
	offset.Add(offset, big.NewInt(1))

	ip := big.NewInt(0).SetBytes(networkIP.Mask(prefix.Mask))
	ip.Add(ip, offset)

	addressBytes := ip.Bytes()
	address := make(net.IP, net.IPv4len)
	copy(address[net.IPv4len-len(addressBytes):], addressBytes)

	return &unikornv1core.IPv4Address{IP: address}, nil
}

// documentationPublicIPPrefix returns RFC 5737 TEST-NET-2 for deterministic,
// non-routable simulated public IP allocation.
func documentationPublicIPPrefix() net.IPNet {
	return net.IPNet{
		IP:   net.IPv4(198, 51, 100, 0).To4(),
		Mask: net.CIDRMask(24, 32),
	}
}

func (p *Provider) loadBalancerNetwork(ctx context.Context, loadBalancer *unikornv1.LoadBalancer) (*unikornv1.Network, error) {
	networkID, ok := loadBalancer.Labels[constants.NetworkLabel]
	if !ok || networkID == "" {
		return nil, fmt.Errorf("%w: load balancer %s missing network label", coreerrors.ErrConsistency, loadBalancer.Name)
	}

	if p.client == nil {
		return nil, fmt.Errorf("%w: kubernetes client not configured", coreerrors.ErrConsistency)
	}

	network := &unikornv1.Network{}
	if err := p.client.Get(ctx, client.ObjectKey{Namespace: loadBalancer.Namespace, Name: networkID}, network); err != nil {
		return nil, fmt.Errorf("%w: get network %s for load balancer %s: %w", coreerrors.ErrConsistency, networkID, loadBalancer.Name, err)
	}

	return network, nil
}

func (p *Provider) CreateLoadBalancer(ctx context.Context, _ *unikornv1.Identity, loadBalancer *unikornv1.LoadBalancer) error {
	if loadBalancer.Spec.RequestedVIPAddress != nil {
		loadBalancer.Status.VIPAddress = loadBalancer.Spec.RequestedVIPAddress.DeepCopy()
	} else {
		network, err := p.loadBalancerNetwork(ctx, loadBalancer)
		if err != nil {
			return err
		}

		if network.Spec.Prefix == nil {
			return fmt.Errorf("%w: network %s missing prefix", coreerrors.ErrConsistency, network.Name)
		}

		vipAddress, err := deterministicIPv4Address(network.Spec.Prefix.IPNet, fmt.Sprintf("simulated-loadbalancer-vip/%s/%s", network.Spec.Prefix.String(), loadBalancer.Name))
		if err != nil {
			return err
		}

		loadBalancer.Status.VIPAddress = vipAddress
	}

	if loadBalancer.Spec.PublicIP {
		publicIP, err := deterministicIPv4Address(documentationPublicIPPrefix(), fmt.Sprintf("simulated-loadbalancer-publicip/%s", loadBalancer.Name))
		if err != nil {
			return err
		}

		loadBalancer.Status.PublicIP = publicIP
	} else {
		loadBalancer.Status.PublicIP = nil
	}

	return nil
}

func (p *Provider) DeleteLoadBalancer(_ context.Context, _ *unikornv1.Identity, _ *unikornv1.LoadBalancer) error {
	return nil
}

// simulatedServer is the process-local provider-side record of a simulated server.
type simulatedServer struct {
	image regionids.ImageID
	// rebuildPassesRemaining is the number of reconcile passes an accepted image
	// change still needs before it converges. Nonzero means a rebuild is in flight.
	rebuildPassesRemaining int
}

// serverRebuildConvergePasses is how many reconcile passes an accepted image
// change yields for before converging. Two passes hold the window open across
// two requeue intervals — long enough for a polling API client to observe it,
// short enough not to drag the integration lane.
const serverRebuildConvergePasses = 2

// serverRebuildHealthMessage is written by both the accept stamp (reconciler
// pass) and the in-flight monitor projection, byte-identical so the two writers
// do not churn the condition, mirroring the OpenStack provider's convention.
const serverRebuildHealthMessage = "unable to determine server status"

// markServerRebuildInFlight stamps the in-flight view: Active Rebuilding and
// health indeterminate, the same shape the OpenStack provider writes for an
// accepted rebuild, so the API projects the documented Rebuilding phase for the
// whole window.
func markServerRebuildInFlight(server *unikornv1.Server) {
	server.SetActiveCondition(unikornv1.ActiveConditionReasonRebuilding)
	server.SetHealthCondition(corev1.ConditionUnknown, unikornv1core.ConditionReasonUnknown, serverRebuildHealthMessage)
}

// markServerSettled stamps the settled view (Active Running, healthy) and the
// observed region. Against a real provider the monitor owns this projection, but
// the simulated record is process-local: the monitor runs in a separate process
// whose provider instance has never seen the server, so the reconcile pass is
// the only writer that can ever report the simulation's steady state.
func markServerSettled(server *unikornv1.Server, record *simulatedServer) {
	server.SetActiveCondition(unikornv1.ActiveConditionReasonRunning)
	server.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "server is healthy")

	setServerObservedStatus(server, record)
}

// CreateServer creates a simulated server and thereafter converges it onto its
// desired image. Create is instantaneous, but an image change opens a bounded
// in-flight window: the pass that accepts it stamps the rebuild view and yields,
// and the change converges only serverRebuildConvergePasses passes later. The
// window exists to make the region's own rebuild lifecycle (reconciler yield →
// provisioning status → settle) observable to API-level tests; provider-contract
// behaviour (Nova's ref-flip, failure presentation) is deliberately not modelled
// here and must be tested against the real provider.
//
// Every non-yield return stamps the settled view and every yield stamps the
// in-flight view, because no other process can (see markServerSettled).
func (p *Provider) CreateServer(_ context.Context, _ *unikornv1.Identity, server *unikornv1.Server, _ *types.ServerCreateOptions) error {
	// No desired image, so there is nothing to converge onto.
	if server.Spec.Image == nil {
		return nil
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	record, ok := p.simulatedServers[server.Name]
	if !ok {
		record = &simulatedServer{
			image: server.Spec.Image.ID,
		}
		p.simulatedServers[server.Name] = record

		markServerSettled(server, record)

		return nil
	}

	// Settled and quiescent.
	if record.rebuildPassesRemaining == 0 && record.image == server.Spec.Image.ID {
		markServerSettled(server, record)

		return nil
	}

	// Accept the image change: open the window and report the in-flight view.
	if record.rebuildPassesRemaining == 0 {
		record.rebuildPassesRemaining = serverRebuildConvergePasses

		markServerRebuildInFlight(server)

		return provisioners.ErrYield
	}

	record.rebuildPassesRemaining--
	if record.rebuildPassesRemaining > 0 {
		markServerRebuildInFlight(server)

		return provisioners.ErrYield
	}

	// Converge onto the current desired image — a change made mid-window wins,
	// the way a re-submitted rebuild would.
	record.image = server.Spec.Image.ID

	markServerSettled(server, record)

	return nil
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

// DeleteServer forgets the simulated server. Deleting one that is already absent
// succeeds: deprovisioning is idempotent.
func (p *Provider) DeleteServer(_ context.Context, _ *unikornv1.Identity, server *unikornv1.Server) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.simulatedServers, server.Name)

	return nil
}

// UpdateServerState projects the simulated server onto the resource the way the
// monitor's poll does against a real provider: it observes and never acts. It
// writes the same views the reconcile pass stamps, byte-identical so in-process
// callers (the create-retry existence check, unit tests) never churn conditions.
// In a deployment it returns not-found for every server: the record is
// process-local and the monitor's provider instance has never seen it, which is
// why CreateServer stamps the settled view itself.
func (p *Provider) UpdateServerState(_ context.Context, _ *unikornv1.Identity, server *unikornv1.Server) error {
	p.lock.RLock()
	defer p.lock.RUnlock()

	record, ok := p.simulatedServers[server.Name]
	if !ok {
		return fmt.Errorf("%w: server %s", coreerrors.ErrResourceNotFound, server.Name)
	}

	if record.rebuildPassesRemaining > 0 {
		markServerRebuildInFlight(server)

		setServerObservedStatus(server, record)

		return nil
	}

	markServerSettled(server, record)

	return nil
}

// setServerObservedStatus writes status.observed under the same single-projection
// ownership rule as the OpenStack provider's function of the same name: one
// fresh read, no arbitration between callers, and an observation that authorizes
// nothing. The simulated ref is always readable so it always overwrites, and the
// simulation has no failed state so the error always clears.
func setServerObservedStatus(server *unikornv1.Server, record *simulatedServer) {
	if server.Status.Observed == nil {
		server.Status.Observed = &unikornv1.ServerObservedStatus{}
	}

	observed := server.Status.Observed
	observed.Generation = server.Generation
	observed.Image = ptr(record.image)
	observed.Error = nil
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
