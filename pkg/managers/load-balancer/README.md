# Load Balancer

This package is the controller factory for `LoadBalancer` reconciliation.

It is structurally standard: it wires the `LoadBalancer` watch into the
load-balancer provisioner, and any spec change triggers a reconcile so provider
state can converge on the desired load-balancer topology.

## Cross-Package Context

- [../../provisioners/managers/load-balancer](../../provisioners/managers/load-balancer/README.md)
  documents the resource-specific provision and deprovision behavior
- [../../providers/internal/openstack](../../providers/internal/openstack/README.md)
  documents the OpenStack Octavia implementation that backs real regions
