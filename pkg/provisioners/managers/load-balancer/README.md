# Load Balancer

`pkg/provisioners/managers/load-balancer` drives controller-side lifecycle for
`LoadBalancer` resources.

Provision resolves the cloud provider and service-principal identity for the
load balancer, resolves the parent `Network` from the resource label, waits for
both the network and identity to be ready, then asks the provider to reconcile
the provider-side load balancer topology.

Deprovision is ordered the other way around: it asks the provider to remove the
provider-side load balancer first, then releases the identity-side quota
allocation.

This package therefore owns the controller boundary between the stored
`LoadBalancer` resource, prerequisite readiness, provider reconciliation, and
allocation cleanup.

## Invariants And Guard Rails

- A load balancer must carry the network label written by the handler layer.
- Provider reconciliation must not begin until both the parent network and the
  service-principal identity are ready.
- Allocation cleanup happens only after provider deletion has succeeded or
  converged idempotently.

## Cross-Package Context

- [../../../providers](../../../providers/README.md) documents the provider
  contract driven by this provisioner
- [../../../providers/internal/openstack](../../../providers/internal/openstack/README.md)
  documents the Octavia implementation for OpenStack-backed regions
- [../../../handler/loadbalancer](../../../handler/loadbalancer/README.md)
  documents API-layer validation, network linkage, and quota allocation
