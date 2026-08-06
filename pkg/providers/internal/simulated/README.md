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
- Determinism matters more than provider fidelity. Built-in flavors,
  volume classes, images, external networks, and synthetic addresses are stable
  by design. Built-in volume classes include stable minimum and maximum capacity
  bounds so higher-layer inventory consumers can exercise the complete neutral
  contract.
- Custom images are stored in-memory behind a lock and merged with built-in
  images through the same query/filter contract used by real providers.
- Unsupported operations fail explicitly with `ErrUnsupportedOperation` rather
  than pretending to succeed.
- Some mutable operations intentionally act by mutating service-side resource
  status deterministically, for example network status and load balancer VIP or
  public IP assignment.
- Servers are simulated deterministically from a process-local record holding the
  image the provider reports the server running. Create is instantaneous. An
  image change opens a bounded in-flight window — the accepting pass stamps the
  rebuild view (Active `Rebuilding`, health indeterminate, the OpenStack
  provider's shape) and yields, converging a fixed number of passes later. The
  window exists so API-level tests can observe the region's own rebuild
  lifecycle (reconciler yield → `provisioning` → settle, and the documented
  `Rebuilding` power state) per PR. The line it deliberately does not cross:
  provider-contract behaviour (Nova's ref-flip at accept, failure presentation,
  task-state vocabulary) is not modelled, because a contract re-encoded into a
  fake and asserted back tests nothing — that behaviour is measured against the
  real provider.
- The record is process-local, and that has a consequence a real provider does
  not have: the monitor runs in a separate process whose own provider instance
  has never seen the server, so its poll gets not-found and writes nothing. The
  reconcile pass is therefore the only writer that can ever report the
  simulation's state — every non-yield `CreateServer` return stamps the settled
  view (Active `Running`, healthy, `status.observed`), and every yield stamps
  the in-flight view.
- `UpdateServerState` implements the monitor-shaped projection for in-process
  callers (the create-retry existence check, unit tests) and never advances the
  simulation, matching the wider design in which the monitor observes and never
  acts. It writes the same views the reconcile pass stamps, byte-identical so
  the writers do not churn conditions: the in-flight view with the pre-rebuild
  image while the window is open, the settled view otherwise.
- `status.observed` is written under the same single-projection ownership rule
  as the OpenStack provider's `setServerObservedStatus`: one fresh read, no
  arbitration between callers, and an observation that authorizes nothing. The
  simulated image ref is always readable so it always overwrites, and the
  simulation has no failed state so `observed.error` always clears.
- `DeleteServer` forgets the record and succeeds for a server that is already
  absent, per the platform specification's idempotent deprovisioning rule.
- The remaining server operations — start, stop, reboot, console session, console
  output, and snapshot — are still explicit unsupported failures.
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
- The in-memory image and server stores are process-local and ephemeral. A restart
  loses every simulated server: the next poll reports the server not found until
  the reconciler recreates it. That is acceptable for test and development use and
  must not be read as provider-restart fidelity.
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
- [../openstack](../openstack/README.md) documents the real image-convergence and
  observation semantics the simulated server lifecycle is a miniature of
- [../../../apis/unikorn/v1alpha1](../../../apis/unikorn/v1alpha1/README.md) owns
  the `Server.Status.Observed` projection rules this package writes under
- [../../../handler](../../../handler/README.md), [../../../monitor](../../../monitor/README.md),
  and higher-order integration tests consume this provider to exercise
  contract-shaped region behaviour without a real cloud
