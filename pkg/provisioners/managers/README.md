# `pkg/provisioners/managers`

This tree contains the per-resource controller provisioners used by region
managers.

The common pattern is:

- hold a typed CRD pointer
- implement `provisioners.ManagerProvisioner`
- use [`../internal/base`](../internal/base/README.md) to resolve provider and
  identity context where needed
- drive provider create/delete or controller-side cleanup

Most of the packages here are intentionally thin. The interesting architectural
differences are not “how do they hook into the controller framework” but which
graph edges they maintain:

- provider-side lifecycle edges
- identity readiness dependencies
- allocation/accounting edges
- explicit reference edges between region resources
- server-side user-data / SSH CA augmentation

## Packages

- [identity](./identity/README.md)
- [network](./network/README.md)
- [security-group](./security-group/README.md)
- [load-balancer](./load-balancer/README.md)
- [server](./server/README.md)
