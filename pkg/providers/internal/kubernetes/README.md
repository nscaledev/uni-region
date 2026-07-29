# pkg/providers/internal/kubernetes

## Intention

`pkg/providers/internal/kubernetes` exposes a Kubernetes-backed region as a
cloud-like substrate for higher-order services.

It does not try to make Kubernetes look identical to OpenStack. Instead, it
adapts a Kubernetes cluster into the subset of the region provider contract
that higher layers need when the backing platform can still satisfy the normal
region-shaped flow in a more abstract way.

That means the consumer is not fixed:

- one consumer might provision Kubernetes-on-Kubernetes clusters, for example
  using `vcluster` with node selectors for placement and segregation
- another could provision VM-style workloads via something like KubeVirt

What matters is that the region exposes a usable flavor/scheduling surface in a
shape higher-order services can consume consistently.

Today this package implements the common read-side provider surface for
Kubernetes regions:

- return the configured `Region`
- connect to the remote cluster using the referenced kubeconfig secret
- discover schedulable node classes
- convert declared node-class metadata into provider-neutral `Flavor` values
- return empty provider-neutral `VolumeClass` inventory

## Links

- [../../../apis/unikorn/v1alpha1](../../../apis/unikorn/v1alpha1/README.md)
- [./ADMIN.md](./ADMIN.md)

The API package defines the `Region.Spec.Kubernetes` shape consumed here.
`ADMIN.md` keeps the cluster-preparation and operator setup guidance that
belongs to human administrators rather than this package contract summary.

## Invariants And Guard Rails

- This package currently implements `types.CommonProvider`, not the full cloud
  provider contract.
- The remote cluster connection is derived from
  `region.Spec.Kubernetes.KubeconfigSecret`.
- Only nodes carrying
  `kubernetes.region.unikorn-cloud.org/node-class` are considered schedulable
  exportable capacity.
- A flavor is exposed only when its node class is both:
  - declared in `region.Spec.Kubernetes.Nodes`
  - observed on at least one node in the remote cluster
- Flavor metadata is primarily taken from `Region.Spec.Kubernetes.Nodes`, not
  auto-derived from raw node objects.
- The package therefore treats the region spec as the authoritative flavor
  description and the cluster as the availability check.
- VolumeClass inventory is empty because this provider does not currently expose
  a block-storage class model.
- Architecture is currently hard-coded to `x86_64`.

## Caveats

- This is a partial provider implementation, not a full Kubernetes analogue of
  the OpenStack provider.
- The trust boundary is large: the referenced kubeconfig currently needs enough
  access to inspect the remote cluster and is described in the admin guidance as
  cluster-admin style access.
- Flavor metadata is manually curated because node status is not treated as a
  sufficient source of truth for all user-facing shape data.
- `Region()` returns the stored region pointer directly and still carries a
  `TODO` about atomic refresh.
- `ListExternalNetworks` and the wider cloud lifecycle operations are not part
  of this package's current implementation surface.

## TODO

- Revisit the hard-coded `x86_64` architecture assumption.
- Tighten the remote cluster trust model if the current kubeconfig access level
  is broader than necessary.

## Cross-Package Context

- [../types](../types/README.md) defines the `CommonProvider` and `Flavor`
  contract this package satisfies
- [../../../handler/region](../../../handler/region/README.md) consumes the
  exported flavor view
- higher-order services use this substrate region shape to implement concrete
  Kubernetes-on-Kubernetes, VM, or similar region-backed provisioning flows
