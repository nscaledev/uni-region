# OpenStack Provider Administration

`pkg/providers/internal/openstack` provides the driver for OpenStack-backed
regions.

## Initial Setup

An OpenStack cloud may be shared with workloads other than UNI. The region
provider therefore avoids requiring a long-lived full administrator credential
at runtime and supports multiple Unikorn deployments cohabiting on the same
cloud, for example staging and production regions.

Install the required OpenStack policies before registering the region. Follow
the instructions in the
[UNI OpenStack Policy repository][policy-repo].

[policy-repo]: https://github.com/nscaledev/uni-python-unikorn-openstack-policy)

## Configure OpenStack Provider Credentials

Use `hack/openstack/configure` to produce the provider environment consumed by
the region registration step. It accepts the usual OpenStack CLI authentication
inputs: a standard `openrc`, existing `OS_*` variables, or `OS_CLOUD`.

The default `create` mode creates or updates the Keystone domain, project, user,
and role grants used by the region provider. Choose a stable prefix for
persistent regions and keep the output in a secret store because it contains the
provider user's password.

```bash
provider_env="${TMPDIR:-/tmp}/gb-north-1.openstack.env"

hack/openstack/configure \
    --openrc /path/to/admin-openrc \
    --prefix gb-north-1 \
    --output "${provider_env}"
```

By default, `configure` grants the provider user these roles:

- domain roles: `member`, `load-balancer_member`, and `manager`
- project roles: `member` and `manager`

Set `UNIKORN_OPENSTACK_INCLUDE_LEGACY_MEMBER_ROLE=true` when targeting older
OpenStack deployments where Neutron still requires the `_member_` role. Override
`UNIKORN_OPENSTACK_DOMAIN_ROLES` or `UNIKORN_OPENSTACK_PROJECT_ROLES` only when
the target cloud's policy model has intentionally diverged from the defaults.

If the provider user already exists, `configure` sets it to the supplied or
generated password. Source the existing provider env file, set
`UNIKORN_OPENSTACK_PASSWORD`, or pass `--password` when re-running the script and
the password must stay stable.

When the OpenStack resources are managed elsewhere, use `existing` mode to
validate and re-emit an already supplied provider env file without creating
domains, projects, users, or role grants:

```bash
. "${provider_env}"

hack/openstack/configure \
    --mode existing \
    --output "${provider_env}"
```

The generated file contains the values needed by region registration:

```bash
UNIKORN_OPENSTACK_AUTH_URL=...
UNIKORN_OPENSTACK_DOMAIN_ID=...
UNIKORN_OPENSTACK_PROJECT_ID=...
UNIKORN_OPENSTACK_USER_ID=...
UNIKORN_OPENSTACK_PASSWORD=...
```

It may also include optional selectors such as
`UNIKORN_OPENSTACK_EXTERNAL_NETWORK_ID`, `UNIKORN_OPENSTACK_FLAVOR_ID`, or
`UNIKORN_OPENSTACK_IMAGE_ID` when those values were supplied or discovered.

## Register The Region

For persistent regions, put the credentials from the provider env file in a
password manager and sync them to Kubernetes as a Secret. The Secret referenced
by the `Region` must contain these keys:

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: unikorn-region
  name: gb-north-1-openstack-credentials
stringData:
  domain-id: ...
  project-id: ...
  user-id: ...
  password: ...
```

Once that Secret exists, use `hack/openstack/register-region` to create or
update the `Region` resource and reference the Secret by name:

```bash
export UNIKORN_OPENSTACK_AUTH_URL=https://openstack.gb-north-1.unikorn-cloud.org:5000

hack/openstack/register-region \
    --namespace unikorn-region \
    --region-id c7e8492f-c320-4278-8201-48cd38fed38b \
    --display-name gb-north-1 \
    --secret-name gb-north-1-openstack-credentials
```

`register-region` references the existing Kubernetes Secret. It does not write
OpenStack credentials to the cluster by default.

For local or test regions where direct Kubernetes Secret creation is acceptable,
pass `--create-secret` with the provider env file:

```bash
hack/openstack/register-region \
    --provider-env "${provider_env}" \
    --namespace unikorn-region \
    --region-id c7e8492f-c320-4278-8201-48cd38fed38b \
    --display-name gb-north-1 \
    --secret-name gb-north-1-openstack-credentials \
    --create-secret
```

Pass `--organization-id` to restrict the region to a single organization. If it
is omitted, the region is visible to all organizations.

`register-region` also prints `REGION_PROVIDER`, `OPENSTACK_REGION_ID`, and
`TEST_REGION_ID` entries for local test environments. Those can be ignored for
persistent region setup.

For additional configuration options for individual OpenStack services, consult
the CRD documentation:

```bash
kubectl explain regions.region.unikorn-cloud.org
```

The resulting `Region` shape is equivalent to:

```yaml
apiVersion: region.unikorn-cloud.org/v1alpha1
kind: Region
metadata:
  namespace: unikorn-region
  name: c7e8492f-c320-4278-8201-48cd38fed38b
  labels:
    unikorn-cloud.org/name: gb-north-1
spec:
  provider: openstack
  openstack:
    endpoint: https://openstack.gb-north-1.unikorn-cloud.org:5000
    serviceAccountSecret:
      namespace: unikorn-region
      name: gb-north-1-openstack-credentials
    identity:
      clusterRoles:
      - member
      - load-balancer_member
```
