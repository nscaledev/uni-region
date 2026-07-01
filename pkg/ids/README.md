# ids

Nominal UUID types for the resource identifiers the region API owns.

## Purpose

Provides distinct named types over `uuid.UUID` for every resource category the
region service addresses through its public API:

| Type | Identifies |
|---|---|
| `RegionID` | regions |
| `IdentityID` | cloud identities |
| `NetworkID` | networks |
| `SecurityGroupID` | security groups |
| `LoadBalancerID` | load balancers |
| `ServerID` | servers |
| `SSHCertificateAuthorityID` | SSH certificate authorities |
| `FileStorageID` | file storage |
| `ImageID` | images |
| `FlavorID` | flavors |

Each type is a distinct named type — not an alias — so the compiler prevents a
`NetworkID` from being passed where a `ServerID` is expected, and so on across
all types.

Each type implements `encoding.TextUnmarshaler` by delegating to `uuid.UUID`,
so the oapi-codegen parameter binder validates UUID format at path-parameter
binding time before any handler is reached. Non-UUID path values produce a
400 at the routing layer rather than propagating into business logic.

## Scope

These types live **at the API layer only**. The region service mints UUIDs for
its own CRD-backed resources (`Region`, `Identity`, `Network`, `SecurityGroup`,
`LoadBalancer`, `Server`, `SSHCertificateAuthority`, `FileStorage`) and addresses
provider-owned `Image`/`Flavor` resources by their provider-assigned UUIDs. The
typed identifiers exist on the generated OpenAPI surface (path parameters and
request/response body fields); handlers convert to plain strings at the boundary
when crossing into Kubernetes object names, labels, provider calls, or CRD
specs, all of which remain string-typed.

Identifiers owned by other services — `organizationId`, `projectId`, `userId` —
use the identity service's [`pkg/ids`](https://github.com/unikorn-cloud/identity/tree/main/pkg/ids)
types, not these. Provider-internal identifiers exposed only through hidden APIs
(`vlanId`, `subnetId`, `routerId`, `serverGroupId`) remain plain strings.

## Conversion

**Inward (string → typed ID):** Use `Parse*` for untrusted input (Kubernetes
labels, request body fields read back from storage). Use `MustParse*` only where
the value is guaranteed valid by a prior validation step — in practice a path
parameter, which the oapi-codegen binder has already validated via
`UnmarshalText` before the handler runs (so re-parsing it cannot panic), or a
test fixture using a known-good literal.

**Outward (typed ID → string):** Call `.String()` to produce the canonical
hyphenated UUID string for Kubernetes object names, label values, provider API
calls, or log messages.
