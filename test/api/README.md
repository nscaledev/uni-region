# Region API tests

Integration (`//go:build integration`) and e2e (`//go:build e2e`) suites live under
`suites/`; shared helpers and fixtures live in this package. Configuration is loaded from
`test/.env` (see `.env.example`).

## Shared test network

Precondition suites (servers, load balancers, file storage, …) do not each create their own
network. They reuse a single long-lived network resolved by `MustResolveSharedNetwork`, so a
run stands up one network instead of many and stops exhausting the org's network quota and the
region's VLAN pool. Only tests whose subject *is* the network — the network lifecycle, cross-org
isolation, and the region ACL deny — create and own their own.

### How it is resolved

`SynchronizedBeforeSuite` resolves the network once (node one) before any specs run:

- It is found by the stable name `SharedTestNetworkName` (`uni-region-e2e-shared`) in the
  configured org/project/region, and reused if present and provisioned.
- If absent, it is created once and **kept** — it persists between runs. No cleanup is
  registered for it.
- The name sits **outside** the `auto-uni-region-` sweep prefix on purpose, so the pre-suite
  stale-resource sweep skips it. Do not rename it into the prefix.
- Duplicates (possible if two cold starts race, since the region API allows duplicate names)
  converge on the oldest; younger duplicates are deleted.

### Reconfiguring it

| What | How |
| -- | -- |
| Name | `SharedTestNetworkName` constant in `shared_network.go` (stable by design). |
| CIDR | `TEST_SHARED_NETWORK_CIDR` in `test/.env` — an uncommon `/24` that must **not** overlap a VAST VIP pool, or File Storage attachment fails silently. It is per-environment; validate on the first File Storage attach and move it if attach fails. |
| Org / project / region | the standard `TEST_ORG_ID` / `TEST_PROJECT_ID` / `TEST_REGION_ID`. |

### Recreating it

The network is long-lived, so a config change (e.g. a new CIDR) does not take effect until it
is recreated. If it is stuck in `error`, or you changed its CIDR, delete it and let the next run
recreate it:

```sh
make reset-shared-network
```

The resolver also fails loudly rather than reusing a broken fixture: an existing network whose
CIDR differs from `TEST_SHARED_NETWORK_CIDR`, or that is in `error`/`deprovisioning` or an
unexpected provisioning state, aborts the run with a message pointing at `reset-shared-network`.
