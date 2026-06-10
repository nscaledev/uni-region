# Region API fuzzing harness (Layer 1)

Property-based / fuzz coverage of the Region service `/api/v2` REST surface using
[Schemathesis](https://schemathesis.readthedocs.io/). It drives every in-scope
operation with generated inputs and asserts the service never returns a server
error and that responses conform to the OpenAPI spec.

## Why this exists, and what it deliberately does not touch

The Region service provisions against a real cloud. Fuzzing a deployment backed
by **real OpenStack** is unsafe — it creates billable resources, exhausts quota,
and leaves orphans on a shared region. This harness therefore targets a
deployment backed by the **simulated provider** (regions `sim-public` /
`sim-private`), where resources are in-memory Kubernetes CRs in a kind cluster
that are discarded on teardown. No OpenStack is involved.

It is **Layer 1**: input-robustness fuzzing of the bearer-token (`oauth2`) API.
Out of scope, by design:

- `/api/v2/servers*` — served over the **internal mTLS API**, a different trust
  boundary (see `test/api/api_client.go`).
- the hidden `/api/v2/networks/{networkID}/references/{reference}` endpoints.
- the legacy hidden `/api/v1/*` nested surface.
- cross-tenant authorization (BOLA) — a separate follow-up.

## Prerequisites

A running simulated-provider Region deployment and a `test/.env` file describing
it. This is exactly what the existing integration harness produces:

```sh
make integration-infra
make integration-install
make integration-fixtures   # writes test/.env
```

On macOS (Docker Desktop), the kind LoadBalancer IP that `test/.env`'s
`REGION_BASE_URL` points at is only reachable from the host while
`cloud-provider-kind` is running. Start it in a separate terminal **before** the
steps above and leave it running, otherwise every request to the Region API
times out or is refused:

```sh
sudo cloud-provider-kind
```

kind clusters do not survive a Docker restart cleanly — container IPs are
reassigned, which strands the IPs baked into `test/.env`. If the deployment
becomes unreachable after a restart, delete and recreate the cluster rather than
reusing it. The fixture credentials are also short-lived (1h); re-run
`make integration-fixtures` if a run is more than an hour after setup.

The harness reads these keys from `test/.env` (or the environment, if already
exported):

| Key | Use |
| --- | --- |
| `REGION_BASE_URL` | Target base URL |
| `REGION_CA_CERT`  | CA bundle the client trusts (no insecure skip-verify) |
| `API_AUTH_TOKEN`  | Bearer token (admin service account) |
| `TEST_ORG_ID`     | Pinned `organizationID` parent reference |
| `TEST_PROJECT_ID` | Pinned `projectID` parent reference |
| `TEST_REGION_ID`  | Pinned `regionID` parent reference (`sim-public`) |

## Running

```sh
make test-api-fuzz
```

That sources `test/.env`, builds a Python virtualenv from `requirements.txt`, and
runs the suite. To run it directly:

```sh
python3 -m venv test/fuzz/.venv
test/fuzz/.venv/bin/pip install -r test/fuzz/requirements.txt
set -a; . test/.env; set +a
test/fuzz/.venv/bin/python -m pytest test/fuzz -q
```

### Knobs

| Env var | Default | Meaning |
| --- | --- | --- |
| `FUZZ_MAX_EXAMPLES` | `50` | Generated examples per operation |
| `FUZZ_SEED` | `0` | Generation seed — fixed for deterministic, replayable runs |

## How it works

1. **Scaffold** (`conftest.py`): the fixture generator pre-creates only the
   org / project / region, so the harness creates the rest of the parent graph
   itself — one network (security groups and load balancers reference its ID),
   one security group, and a storage-class lookup — and tears them down at the
   end of the session.
2. **Pinning** (`pinning.py`): each generated case has its *parent-reference*
   fields only (query `organizationID`/`projectID`/`regionID`/`networkID`, path
   `regionID`/`networkID`/`securityGroupID`, and body `spec.*` parent ids)
   overwritten with the real IDs, so requests route to real resources and reach
   handler logic instead of 404ing. Everything else stays fuzzed.

   Pinning also supplies valid values for a small set of fields whose constraint
   **cannot be expressed in OpenAPI** — load balancer `vipAddress` (must fall
   within the network CIDR; dropped, as it is optional) and SSH CA `publicKey`
   (must be a valid OpenSSH key; pinned to a real key). Without this, positive-
   data generation produces values the server correctly rejects with 422 — a
   false positive. This is deliberately *not* done for constraints that **are**
   expressible in the schema (e.g. CIDR `format` on a network `prefix`): those
   rejections are genuine spec-looseness findings and must stay visible.
3. **Checks**: `call_and_validate` runs Schemathesis' default checks minus
   three exclusions — the primary signal is `not_a_server_error` (any unhandled
   5xx is a bug), plus status-code / content-type / response-schema /
   response-header conformance against the spec. Excluded:

   - `positive_data_acceptance` / `negative_data_rejection` — both reason about
     whether the *generated* request was schema-valid, but pinning rewrites
     fields after generation, so that judgement no longer describes the request
     actually sent. They produce structurally guaranteed false positives here
     (e.g. a deliberately-invalid `spec.regionId` is pinned back to a real one,
     the server rightly accepts it, and the check reports a failure).
   - `unsupported_method` — probes methods like `TRACE`, which the nginx
     ingress answers itself (405, HTML body); the response never reaches the
     Region service, so the check measures the ingress, not the code under
     test.

`DELETE` by-id cases are left with fuzzed (random) IDs so they exercise the
not-found path without destroying the scaffold mid-run.

## Triaging a failure

Schemathesis prints a reproducible cURL command and the generation seed for any
failing case. Re-run with the same `FUZZ_SEED` to reproduce. Confirmed defects
should be distilled into a deterministic Ginkgo case under `test/api/suites/`
rather than relying on the fuzzer to re-find them.

## Caveats

- POST cases with valid parent refs create real (simulated) resources that are
  not individually cleaned up; they are bounded and discarded when the kind
  cluster is torn down.
- The spec `$ref`s the shared `unikorn-core` common spec over HTTPS, so loading
  it requires egress to `raw.githubusercontent.com`.
- The fixture bearer token is short-lived (default 1h); keep a run shorter than
  the token lifetime.
