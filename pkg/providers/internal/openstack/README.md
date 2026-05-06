# Unikorn OpenStack Provider

Provides a driver for OpenStack based regions.

## Initial Setup

It is envisaged that an OpenStack cluster may be used for things other than the exclusive use of Unikorn, and as such it tries to respect this as much as possible.
We also operate under the principle of least privilege, so don't want to have a full admin credential lying around.

In particular we want to allow different instances of Unikorn to cohabit to support, for example, staging environments.

We need a number of policies installing to function correctly.
Follow the instructions in the [Unikorn OpenStack Policy repository](https://github.com/unikorn-cloud/python-unikorn-openstack-policy) to install them.

### OpenStack Platform Configuration

Use `hack/openstack/configure` to produce the provider environment consumed by
the region registration step. It can use a standard `openrc`, `OS_*` variables,
or `OS_CLOUD`.

Set `UNIKORN_OPENSTACK_INCLUDE_LEGACY_MEMBER_ROLE=true` when targeting older OpenStack deployments where Neutron still requires the `_member_` role.

The default `create` mode is useful when Unikorn should own the provider domain,
project, user, and role grants. Choose a stable prefix for persistent regions and
keep the output in a secret store; it contains the provider password.

```bash
provider_env="${TMPDIR:-/tmp}/gb-north-1.openstack.env"

hack/openstack/configure \
    --openrc /path/to/admin-openrc \
    --prefix gb-north-1 \
    --output "${provider_env}"
```

If the provider user already exists, `configure` will not reset its password by
default. Source the existing provider env file, or otherwise supply
`UNIKORN_OPENSTACK_PASSWORD`, when re-running it. Use `--rotate-password` only
when you intentionally want to reset the existing OpenStack user password.

When OpenStack resources are managed elsewhere, use `existing` mode to validate
and re-emit an already supplied provider env file without creating OpenStack
resources:

```bash
. "${provider_env}"

hack/openstack/configure \
    --mode existing \
    --output "${provider_env}"
```

The generated file contains entries which can be used to create a region:

```bash
UNIKORN_OPENSTACK_AUTH_URL=...
UNIKORN_OPENSTACK_DOMAIN_ID=...
UNIKORN_OPENSTACK_PROJECT_ID=...
UNIKORN_OPENSTACK_USER_ID=...
UNIKORN_OPENSTACK_PASSWORD=...
```

### Unikorn Configuration

When we create a `Region` of type `openstack`, it will require a secret that contains credentials.

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

Once that Secret exists, register the `Region` and reference it by name:

```bash
export UNIKORN_OPENSTACK_AUTH_URL=https://openstack.gb-north-1.unikorn-cloud.org:5000

hack/openstack/register-region \
    --namespace unikorn-region \
    --region-id c7e8492f-c320-4278-8201-48cd38fed38b \
    --display-name gb-north-1 \
    --secret-name gb-north-1-openstack-credentials
```

`register-region` creates the `Region` resource and references the existing
Kubernetes Secret. It does not write OpenStack credentials to the cluster by
default.

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

It also prints `REGION_PROVIDER`, `OPENSTACK_REGION_ID`, and `TEST_REGION_ID`
entries for local test environments; those can be ignored for persistent region
setup.

Pass `--organization-id` to restrict a region to a single organization. If it is
omitted, the region is visible to all organizations.

For additional configuration options for individual OpenStack services, consult `kubectl explain regions.region.unikorn-cloud.org` for documentation.

```yaml
apiVersion: region.unikorn-cloud.org/v1alpha1
kind: Region
metadata:
  # Use "uuidgen -r" to select a random ID, this MUST start with a character a-f.
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
