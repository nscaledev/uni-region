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

These types run from the router down to the provider layer — not the API layer
alone. The region service mints UUIDs for its own CRD-backed resources (`Region`,
`Identity`, `Network`, `SecurityGroup`, `LoadBalancer`, `Server`,
`SSHCertificateAuthority`, `FileStorage`) and addresses provider-owned
`Image`/`Flavor` resources by their provider-assigned UUIDs. They appear on:

- the generated OpenAPI surface (path parameters and request/response body fields);
- **CRD spec fields** that hold region-owned UUIDs — currently the `Server` CRD's
  `FlavorID`, `Image.ID`, `SecurityGroups[].ID` and `Networks[].ID`. Because the
  types are `uuid.UUID`-backed (`[16]byte`), each declaration carries
  `+kubebuilder:validation:Type=string` (and `Format=uuid`) so controller-gen
  emits a string schema rather than a byte array; the existing `TextMarshaler`
  handles the etcd round-trip, so no data migration is needed;
- the **provider interface** for image operations (`GetImage`, `DeleteImage`, and
  the `AvailableToOrganization`/`OwnedByOrganization` query predicates). The other
  provider methods take whole CRD objects and so carry their typed IDs inside the
  object — no signature change needed.

Conversion back to a plain string happens only at genuine sinks: an external
provider SDK call (gophercloud/OpenStack), a by-name Kubernetes lookup
(`GetRaw`/`ObjectKey`), a label value, or a read-model/status field still
string-typed by design (e.g. v1 `ServerNetwork.Id`, `ServerSecurityGroup.Id`).
Resources recover their own and their owners' typed IDs fail-closed from names
and labels via accessor methods on the CRD types (`Network.NetworkID()`,
`Server.RegionID()`, `*.OrganizationID()`/`OrganizationAndProjectID()`).

Identifiers owned by other services — `organizationId`, `projectId`, `userId` —
use the identity service's [`pkg/ids`](https://github.com/unikorn-cloud/identity/tree/main/pkg/ids)
types, not these. Provider-internal identifiers exposed only through hidden APIs
(`vlanId`, `subnetId`, `routerId`, `serverGroupId`) remain plain strings — they
live in another system's namespace, not region's.

## Conversion

**Inward (string → typed ID):** Use `Parse*` for untrusted or stored input
(Kubernetes labels, resource names, request body fields read back from storage);
it returns an error so a malformed value fails closed rather than panicking. The
panic-on-error `MustParse*` constructors live in the test-only
[`idstest`](idstest) package — not here — so they cannot be reached on a request
path; use them only with known-good literals in tests. Path parameters are
validated by the oapi-codegen binder via `UnmarshalText` before the handler runs.

**Outward (typed ID → string):** Call `.String()` to produce the canonical
hyphenated UUID string — only at the sinks above (external SDK calls, by-name
Kubernetes lookups, label values, string read-model fields, log messages).
