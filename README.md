# Region

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

For further info see the [OpenStack provider documentation](pkg/providers/internal/openstack/README.md).

### Kubernetes

Kubernetes regions allow Kubernetes clusters from any cloud provider to be consumed and increase capacity without the hassle of physical infrastructure.
Kubernetes regions are exposed to end users with virtual Kubernetes clusters.

For further info see the [Kubernetes provider documentation](pkg/providers/internal/kubernetes/README.md).

## Installation

### Prerequisites

The use the Kubernetes service you first need to install:

* [The identity service](https://github.com/nscaledev/uni-identity) to provide API authentication and authorization.

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

## Running Tests

### Local Testing

1. Copy the example config:
   ```bash
   cp test/.env.example test/.env
   ```

2. Update `test/.env` with your values:
   - `API_BASE_URL` - Region API server URL
   - `API_AUTH_TOKEN` - Service token from console
   - `TEST_ORG_ID`, `TEST_PROJECT_ID`, `TEST_REGION_ID` - Test data IDs

3. Run tests:
   ```bash
   make test-api                                              # Run all tests
   make test-api-verbose                                      # Verbose output
   make test-api-focus FOCUS="should return all available"   # Run focused tests
   ```

### GitHub Actions

Trigger the workflow manually from the Actions tab:
1. Go to **Actions** → **API Tests**
2. Click **Run workflow**
3. View results in the workflow run and download test artifacts

## Contract Testing

Contract tests verify that the provider service meets consumer expectations defined in the Pact Broker.

### Prerequisites

1. Install Pact FFI library (macOS):
   ```bash
   brew tap pact-foundation/pact-ruby-standalone
   brew install pact-ruby-standalone
   mkdir -p $HOME/Library/pact
   cp /usr/local/opt/pact-ruby-standalone/libexec/lib/*.dylib $HOME/Library/pact/
   ```

2. Start Pact Broker (optional, for local testing):

Download the Uni-core repo and run the following command from its root dir:
   ```bash
make pact-broker-start
   ```

### Running Provider Contract Tests

Run verification against pacts from the Pact Broker (this assumes you have already run and published the consumer tests to the broker):
```bash
make test-contracts-provider
```

Run verification against a local pact file (pact for the consumer when testing without a broker):
```bash
make test-contracts-provider-local PACT_FILE=/path/to/pact.json
```

Run with verbose output:
```bash
make test-contracts-provider-verbose
```

### Writing Provider Tests

Provider tests are located in `test/contracts/provider/{consumer}/`. Each consumer has:
- `verify_test.go` - Main test setup and verification
- `states.go` - State handlers for setting up test data
- `middleware.go` - Test-specific middleware (e.g., mock ACL)

**Basic Pattern:**

1. **Test Structure** (`verify_test.go`):
   - Uses Ginkgo/Gomega for BDD-style tests
   - Starts a test server in `BeforeEach`
   - Creates state handlers mapping Pact states to setup functions
   - Runs verification using `provider.NewVerifier()`

2. **State Handlers** (`states.go`):
   - Implement parameterized state handlers that accept organization ID and other parameters
   - Use `StateManager` to create/cleanup Kubernetes resources
   - Follow the builder pattern for creating test resources (see `RegionBuilder`)

3. **Example State Handler:**
   ```go
   func (sm *StateManager) HandleOrganizationState(ctx context.Context, setup bool, params map[string]interface{}) error {
       orgID := getStringParam(params, ParamOrganizationID, "test-org")
       regionType := getStringParam(params, ParamRegionType, "")
       
       if setup {
           return sm.setupRegions(ctx, orgID, regionType)
       }
       return sm.cleanupAllRegions(ctx)
   }
   ```

4. **State Constants:**
   - Define state names as constants (must match consumer contract states)
   - Use parameter keys for passing data to state handlers

See `test/contracts/provider/compute/` for a complete example following this pattern.

## What Next?

The region controller is useless as it is, and requires a service provider to use it to yield a consumable resource.
Try out the [Kubernetes service](https://github.com/nscaledev/uni-kubernetes).
