# Unikorn Kubernetes Provider

The Kubernetes provider allows entire Kubernetes clusters to be used as regions.
While these regions do not provide the isolation inherent with virtual and physical machines, they can be provisioned into light-weight and highly performant virtual clusters.

The Unikorn Kubernetes service can consume Kubernetes regions for cluster provisioning.

## Kubernetes Cluster Prerequisites

Before importing a Kubernetes cluster as a region, some steps need to be carried out in order to make it consumable.

### Flavor Mapping

Kubernetes clusters are composed of pools of machines.
Each machine type has a set of characteristics:

* CPU count and type
* Memory capacity
* Ephemeral disk capacity
* GPU count and type

These characteristics are directly exposed by the region controller a flavors, thus allowing virtual clusters to be composed of pools of entire nodes.
This facilitates node level isolation, simplified quota management based on nodes and GPUs, and finally simplified billing based on node flavors (as opposed to pod resource limits).

Node characteristic data can also bu used to find a suitable region to run a workload on given the requirement for a certain GPU type, for example.

Each node of a certain machine type must have a `kubernetes.region.unikorn-cloud.org/node-class` node label applied.
The value of the label should be a globally unique v4 UUID.

Only nodes with a node class label can be considered and consumed by higher order services such as the Kubernetes service's virtual clusters.

Node class metadata is defined by the region resource, e.g.:

```yaml
apiVersion: region.unikorn-cloud.org/v1alpha1
kind: Region
metadata:
  namespace: unikorn-region
  name: fe4ecbe4-421d-4f25-8b11-69593adfef5d
  labels:
    unikorn-cloud.org/name: de-central-0
spec:
  provider: kubernetes
  kubernetes:
    kubeConfigSecret:
      namespace: unikorn-region
      name: de-central-0-kubeconfig
    nodes:
    - id: 4be04a2e-87e6-4ff2-b34b-2994ee1600ba
      name: bratwurst
      cpu:
        count: 2
      disk: 40Gi
      memory: 4Gi
```

### Kubernetes Service Prerequisites

The Kubernetes service uses Loft vCluster to provide light-weight virtual clusters for end users.
By default, the vCluster Helm chart assumes the `ingress-nginx` controller is installed, and also able to operate in TLS pass-through mode in order to propagate the Kubernetes configuration client certificate to the virtual API endpoint for authentication and authorization.

This can be installed in a similar manner to the following:

```shell
helm upgrade --install nginx-ingress nginx/ingress-nginx -n ingress-nginx --create-namespace --set controller.ingressClassResource.default=true --set 'controller.extraArgs.enable-ssl-passthrough='
```

As the ingress needs to be able to route the correct clients to the correct virtual cluster API endpoint via the shared ingress, we need to be able to use SNI in order to extract the HTTP hostname from the TLS handshake to perform the routing.
For hostname based routing, we need to have DDNS available to manage DNS records.
This is typically achieved with the `external-dns` controller:

```shell
helm upgrade --install external-dns external-dns/external-dns -n external-dns --create-namespace --set provider.name=cloudflare --set env[0].name=CF_API_TOKEN --set env[0].value=foo --set domainFilters[0]=my-region.domain.com
```

Finally when we install virtual clusters, they need to be monitored, and therefore require Prometheus:

```shell
helm upgrade --install kube-prometheus kube-prometheus prometheus-community/kube-prometheus-stack --create-namespace -n kube-prometheus
```
