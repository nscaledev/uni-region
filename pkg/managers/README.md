# `pkg/managers`

This tree contains the controller factories that wrap region provisioners in the
shared `core/pkg/manager` controller framework.

The common pattern is:

- initialize a shared provider registry once per controller process
- expose service metadata and any controller-specific CLI options
- create a reconciler from a typed provisioner constructor
- register a watch on one CRD with a generation-changed predicate

So the managers layer is thin by design. Its job is controller composition, not
resource policy.

The main shared piece is [providers.go](./providers.go), which performs the
provider registry bootstrap with a direct client for warm-up and a cached client
for normal operation.

## Packages

- [identity](./identity/README.md)
- [network](./network/README.md)
- [security-group](./security-group/README.md)
- [load-balancer](./load-balancer/README.md)
- [server](./server/README.md)
