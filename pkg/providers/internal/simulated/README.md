# pkg/providers/internal/simulated

## Intention

`pkg/providers/internal/simulated` is a deterministic contract-shaped provider
used to push broad region integration testing left.

It exists primarily so higher-order region flows can be exercised in pull
request and development environments without requiring a real cloud backing
environment. That makes it valuable for:

- broad integration coverage of provider-shaped flows
- race and bottleneck detection in higher layers
- high-scale and performance-oriented testing where a real cloud deployment
  would be impractical

It is not intended to be a faithful emulator of OpenStack. It deliberately
implements only enough of the provider contract to support useful testing and
development, while keeping behaviour deterministic and cheap to run.

## Invariants And Guard Rails

- The package implements the full `types.Provider` interface, but only some
  operations have meaningful simulated behaviour.
- The current implementation is deliberately incomplete. It represents the
  smallest useful amount of work needed to unlock broad push-left integration
  coverage, not a mature simulation of the full provider surface.
- Determinism matters more than provider fidelity. Built-in flavors, images,
  external networks, and synthetic addresses are stable by design.
- Custom images are stored in-memory behind a lock and merged with built-in
  images through the same query/filter contract used by real providers.
- Unsupported operations fail explicitly with `ErrUnsupportedOperation` rather
  than pretending to succeed.
- Some mutable operations intentionally act by mutating service-side resource
  status deterministically, for example network status and load balancer VIP or
  public IP assignment.
- Server create/delete/state operations are deliberately shallow but successful:
  create marks the Server running and derives deterministic addresses when the
  referenced network information is available. This exists to exercise
  higher-layer server workflows in integration tests without requiring a real
  cloud.
- The simulated provider is particularly useful for stressing strongly
  consistent higher-layer workflows such as quota, reference, and coordination
  paths, because those higher layers can be exercised against a cheap
  deterministic backend without a real cloud dominating the test environment.

## Caveats

- This is a contract stub, not a high-fidelity cloud emulator.
- Large parts of the real OpenStack behaviour surface are intentionally absent.
  Success here does not prove fidelity against real provider edge cases,
  eventual-consistency quirks, or provider-specific failures.
- More work is still needed before this provider can support meaningfully deep
  provider-level testing. Its value today is breadth, determinism, and scale,
  not behavioural completeness.
- Some operations are no-ops, some are deterministic state mutations, and some
  are explicit unsupported failures. Callers must not assume one consistent
  simulation strategy across the whole interface.
- The in-memory image store is process-local and ephemeral.
- The package still writes transitional compatibility state such as
  `Network.Status.Openstack`, so it inherits some of the same historical baggage
  as the wider repo.

## TODO

- Extend the simulation only where it improves contract, race, bottleneck, or
  scale testing value; do not grow it into a full fake OpenStack by default.
- Remove simulated writes to transitional status shapes as the corresponding
  compatibility fields disappear from the wider system.

## Cross-Package Context

- [../types](../types/README.md) defines the full provider contract this package
  implements
- [../../../handler](../../../handler/README.md), [../../../monitor](../../../monitor/README.md),
  and higher-order integration tests consume this provider to exercise
  contract-shaped region behaviour without a real cloud
