# Unikorn Region Manager

![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/light-on-dark/logo.svg#gh-dark-mode-only)
![Unikorn Logo](https://raw.githubusercontent.com/unikorn-cloud/assets/main/images/logos/dark-on-light/logo.svg#gh-light-mode-only)

Unikorn's centralized region discovery and routing service.

## Architecture

Unikorn is a composable suite of different microservices that provide different functionality.

Hardware provisioning can come in a number of different flavors, namely bare-metal, managed Kubernetes etc.
These services have a common requirement on a compute cloud/region to provisiong projects, users, roles, networking etc. in order to function.

### A Note on Security

At present this region controller is monolithic, offering region discovery and routing to allow scoped provisioning and deprovisioning or the aforementioned hardware prerequisites.

Given this service holds elevated privilege credentials to all of those clouds, it make it somewhat of a honey pot.
Eventually, the goal is to have this act as a purely discovery and routing service, and platform specific region controllers live in those platforms, including their credentials.
The end goal being the compromise of one, doesn't affect the others, limiting blast radius, and not having to disseminate credentials across the internet, they would reside locally in the cloud platform's AS to improve security guarantees.
