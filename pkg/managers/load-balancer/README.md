# Load Balancer

This package is the controller factory for `LoadBalancer` reconciliation.

It is structurally standard, but it points at a provisioner whose current
behaviour is asymmetric: mostly teardown/allocation cleanup rather than a full
provider create path.
