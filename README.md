# Region

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

Centralized region discovery and routing service.

## Architecture

We provide a composable suite of different micro-services that provide different functionality.

Hardware provisioning can come in a number of different flavors, namely bare-metal, managed Kubernetes etc.
These services have a common requirement on a compute cloud/region to provision projects, users, roles, networking etc. in order to function.

### A Note on Security

At present this region controller is monolithic, offering region discovery and routing to allow scoped provisioning and deprovisioning or the aforementioned hardware prerequisites.

Given this service holds elevated privilege credentials to all of those clouds, it make it somewhat of a honey pot.
Eventually, the goal is to have this act as a purely discovery and routing service, and platform specific region controllers live in those platforms, including their credentials.
The end goal being the compromise of one, doesn't affect the others, limiting blast radius, and not having to disseminate credentials across the internet, they would reside locally in the cloud platform's AS to improve security guarantees.

## Supported Providers

### OpenStack

OpenStack is an open source cloud provider that allows on premise provisioning of virtual and physical infrastructure.
It allows a vertically integrated stack from server to application, so you have full control over the platform.
This obviously entails a support crew to keep it up and running!

For further info see the [OpenStack provider documentation](pkg/providers/openstack/README.md).

### Kubernetes

Kubernetes regions allow Kubernetes clusters from any cloud provider to be consumed and increase capacity without the hassle of physical infrastructure.
Kubernetes regions are exposed to end users with virtual Kubernetes clusters.

For further info see the [Kubernetes provider documentation](pkg/providers/kubernetes/README.md).

## Installation

### Prerequisites

The use the Kubernetes service you first need to install:

* [The identity service](https://github.com/unikorn-cloud/identity) to provide API authentication and authorization.

### Installing the Service

The region service is typically installed with Helm as follows:

```yaml
region:
  ingress:
    host: region.unikorn-cloud.org
    clusterIssuer: letsencrypt-production
    externalDns: true
  oidc:
    issuer: https://identity.unikorn-cloud.org
regions:
- name: gb-north-1
  provider: openstack
  openstack:
    endpoint: https://my-openstack-endpoint.com:5000
    serviceAccountSecret:
      namespace: unikorn-region
      name: gb-north-1-credentials # See the provider setup section
```

The configures the service to be exposed on the specified host using an ingress with TLS and DDNS.

The OIDC configuration allows token validation at the API.

Regions define cloud instances to expose to clients.

## What Next?

The region controller is useless as it is, and requires a service provider to use it to yield a consumable resource.
Try out the [Kubernetes service](https://github.com/unikorn-cloud/kubernetes).
