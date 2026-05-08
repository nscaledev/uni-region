# pkg/providers/allocation/vlan

## Intention

`pkg/providers/allocation/vlan` is a region-local coordination package for
allocating VLAN IDs for OpenStack provider networks.

It exists because OpenStack does not allocate those provider-network VLAN IDs
for us, while some provisioning paths, especially provider-network and
baremetal-oriented flows, still need a concrete VLAN assignment. This package
therefore keeps the platform's own allocation table in Kubernetes and hands out
VLAN IDs on behalf of the provider integration.

This is not a generic network allocator or a full IPAM system. It is a narrow
bookkeeping layer for one specific gap in the underlying provider model.

## Links

- [../../../apis/unikorn/v1alpha1](../../../apis/unikorn/v1alpha1/README.md)

`pkg/apis/unikorn/v1alpha1` defines the `VLANAllocation` coordination object
and the `Region` VLAN/provider-network configuration that this allocator uses.

## Invariants And Guard Rails

- Allocation scope is per region. Each allocator instance uses the region
  namespace and `region.StaticName()` to locate a single `VLANAllocation`
  record for that region.
- The allocatable set comes from `region.VLANSpec()`. If no explicit VLAN
  segment configuration is present, the allocator falls back to the full valid
  VLAN range `1..4094`.
- Invalid or partially invalid configured ranges are clamped defensively rather
  than trusted blindly.
- Allocation is first-fit over the allocatable set, not preference-aware or
  topology-aware.
- Persistence and concurrency coordination rely on the backing Kubernetes
  `VLANAllocation` object rather than in-memory state.
- `Free()` is idempotent.
- If the allocation table contains the same VLAN ID more than once, the package
  treats that as corruption and returns an allocation error rather than trying
  to guess how to repair it.

## Caveats

- This package compensates for a provider limitation. It should not be mistaken
  for a general platform-wide network allocation abstraction.
- Allocation is currently an exhaustive search with an admitted `O(n^2)`
  worst-case shape, though the problem space is bounded.
- Ownership is only recorded as `networkID` in the allocation table, but
  deallocation is keyed by VLAN ID alone. Correctness therefore depends on
  higher layers calling `Free()` with the right VLAN ID.
- If an operator manually corrupts the `VLANAllocation` object, this package can
  detect some bad states but does not provide a repair or reconciliation model.
- Falling back to the full VLAN range when no explicit segments are configured
  is convenient, but it can be too broad for environments that expect strict
  administrative partitioning.

## TODO

- Replace the current exhaustive search if allocation scale or churn ever makes
  the bounded `O(n^2)` behaviour operationally painful.
- Re-evaluate whether this allocator should continue to exist if a future
  provider path can source-of-truth VLAN allocation elsewhere.

## Cross-Package Context

- [../../internal/openstack](../../internal/openstack/README.md) invokes this
  allocator when provider-network provisioning needs a VLAN
- [../../../apis/unikorn/v1alpha1](../../../apis/unikorn/v1alpha1/README.md)
  defines the persisted `VLANAllocation` state and region-side VLAN
  configuration
