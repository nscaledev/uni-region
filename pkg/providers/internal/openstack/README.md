# Unikorn OpenStack Provider

Provides a driver for OpenStack based regions.

## Initial Setup

It is envisaged that an OpenStack cluster may be used for things other than the exclusive use of Unikorn, and as such it tries to respect this as much as possible.
We also operate under the principle of least privilege, so don't want to have a full admin credential alyng around.

In particular we want to allow different instances of Unikorn to cohabit to support, for example, staging environments.

We need a number of policies installing to function correctly.
Follow the instructions in the [Unikorn OpenStack Policy repository](https://github.com/unikorn-cloud/python-unikorn-openstack-policy) to install them.

### OpenStack Platform Configuration

Start by selecting a unique name that will be used for the deployment's name, project, and domain:

```bash
export USER=unikorn-staging
export DOMAIN=unikorn-staging
export PROJECT=unikorn-default
export PASSWORD=$(apg -n 1 -m 24)
```

#### Create the domain.

The use of project domains for projects deployed to provision Kubernetes cluster achieves a few aims.
First namespace isolation.
Second is a security consideration.
It is dangerous, anecdotally, to have a privileged process that has the power of deletion.
By limiting the scope of list operations to that of the project domain we limit our impact on other tenants on the system.
A domain may also aid in simplifying operations like auditing and capacity planning.

```bash
DOMAIN_ID=$(openstack domain create ${DOMAIN} -f json | jq -r .id)
```

#### Create the project.

As the OpenStack provider for the region controller also functions as a client in order to retrieve information such as available images, flavors, and so on it also needs to be associated with a project so that the default policy for various API requests is correctly satisfied:

```bash
PROJECT_ID=$(openstack project create $PROJECT --domain $DOMAIN -f json | jq -r .id)
```

#### Create the user.

```bash
USER_ID=$(openstack user create --domain ${DOMAIN_ID} --password ${PASSWORD} ${USER} -f json | jq -r .id)
```

### Grant any roles to the user.

When a Kubernetes cluster is provisioned, it will be done using application credentials, so ensure any required application credentials as configured for the region are explicitly associated with the user here.

> [!NOTE]
> It may be necessary to add the `_member_` role on older OpenStack deployments where Neutron requires it to function.

```bash
for role in member load-balancer_member manager; do
	openstack role add --user ${USER_ID} --domain ${DOMAIN_ID} ${role}
done
```

Grant the `member` role on the project we created in a previous step:

```bash
openstack role add --user ${USER_ID} --project ${PROJECT_ID} member
```

### Unikorn Configuration

When we create a `Region` of type `openstack`, it will require a secret that contains credentials.
This can be configured as follows.

```bash
kubectl create secret generic -n unikorn-region gb-north-1-credentials \
    --from-literal=domain-id=${DOMAIN_ID} \
    --from-literal=project-id=${PROJECT_ID} \
    --from-literal=user-id=${USER_ID} \
    --from-literal=password=${PASSWORD}
```

Finally we can create the region itself, although this should be statically configured via Helm.
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
      namespace: unikorn
      name: gb-north-1-credentials
```

Cleanup actions.

```bash
unset DOMAIN
unset DOMAIN_ID
unset USER
unset USER_ID
unset PASSWORD
unset PROJECT
unset PROJECT_ID
```
