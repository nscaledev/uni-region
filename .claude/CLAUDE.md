# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Uni-region is a centralized region discovery and routing service for the Unikorn Cloud platform. It provides a composable suite of microservices that manage different cloud provider regions (OpenStack, Kubernetes) and exposes compute resources (flavors, images, networks, servers) via a unified REST API.

The service acts as a central control plane for provisioning infrastructure prerequisites (projects, users, roles, networking) across multiple cloud providers. It includes multiple specialized controllers and a REST API server for managing region resources.

## Development Commands

### Building
```bash
# Build all controller binaries for your architecture
make

# Build specific controller
make bin/$(go env GOARCH)-linux-gnu/unikorn-region-controller
make bin/$(go env GOARCH)-linux-gnu/unikorn-server-controller

# Build Docker images for local development
make images

# Build cross-platform images for release
RELEASE=1 make images

# Load images into kind cluster
make images-kind-load
```

### Testing
```bash
# Run unit tests with coverage
make test-unit

# View coverage in browser (generates cover.html)
go tool cover -html cover.out -o cover.html

# Run API integration tests (requires test/.env configuration)
make test-api

# Run specific API test with detailed logging
make test-api-focus FOCUS="should return all available"

# Run tests verbosely
make test-api-verbose

# Run tests in parallel
make test-api-parallel
```

#### API Test Configuration
API tests require environment configuration. Copy `test/.env.example` to `test/.env` and configure:
- `API_BASE_URL` - Region API server URL
- `API_AUTH_TOKEN` - Service token from console
- `TEST_ORG_ID`, `TEST_PROJECT_ID`, `TEST_REGION_ID` - Test resource IDs

Note: `.env`, `.env.dev`, and `.env.uat` are gitignored and contain sensitive credentials.

### Code Generation
```bash
# Generate OpenAPI types, client, and router from server.spec.yaml
make pkg/openapi/types.go pkg/openapi/client.go pkg/openapi/router.go

# Generate Kubernetes CRDs from API types
make $(CRDDIR)

# Generate deepcopy methods for Kubernetes types
make $(GENDIR)

# Generate all code (run after modifying OpenAPI spec or API types)
make generate
```

### Linting
```bash
# Run golangci-lint (version v2.1.5)
make lint

# Install linter locally
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.5
golangci-lint run --timeout=10m ./...

# Validate OpenAPI schema
make validate

# Validate docs generation
make validate-docs

# Check license headers
make license
```

### Helm Charts
```bash
# Package charts
make charts

# Package and push charts (requires RELEASE=1)
RELEASE=1 make charts
```

## Architecture

### Core Components

#### Controllers (8 Kubernetes Controllers)
Located in `cmd/unikorn-*/main.go`, each controller manages specific Kubernetes resources:
- **unikorn-region-controller**: Reconciles `Region` CRDs, manages region lifecycle
- **unikorn-identity-controller**: Manages identity resources (projects, users, roles)
- **unikorn-network-controller**: Manages network provisioning
- **unikorn-security-group-controller**: Manages security groups and rules
- **unikorn-server-controller**: Manages compute server resources
- **unikorn-file-storage-controller**: Manages file storage resources
- **unikorn-region-project-consumer**: Handles project-level resource consumption
- **unikorn-region-monitor**: Monitors region health and status

All controllers follow the controller-runtime pattern and register custom resource schemes from `pkg/apis/unikorn/v1alpha1/`.

#### API Layer (`pkg/handler/`)
REST API handlers implement OpenAPI specification (`pkg/openapi/server.spec.yaml`):
- `handler.go`: Main handler coordinating sub-handlers
- `handler_image.go`: Image listing and filtering
- `handler_v2_server.go`: Server (compute instance) operations
- Sub-packages: `region/`, `identity/`, `network/`, `securitygroup/`, `server/`, `storage/`, `image/`

Each handler provides CRUD operations and translates between OpenAPI types and Kubernetes CRDs.

#### Provider Abstraction (`pkg/providers/`)
Abstracts different cloud backends behind a common interface (`types.Provider`):
- `internal/openstack/`: OpenStack provider implementation
- `internal/kubernetes/`: Kubernetes provider implementation
- `types/`: Shared types (Flavor, Image, ExternalNetwork)
- `providers.go`: Provider factory with caching

Providers are instantiated via `providers.New(ctx, client, namespace, regionID)` and cached by region ID.

#### Custom Resources (`pkg/apis/unikorn/v1alpha1/`)
Kubernetes CRDs define the data model:
- `Region`: Top-level resource representing a cloud region
- `RegionSpec`: Provider-specific configuration (OpenStack/Kubernetes)
- Provider-specific types for compute, networking, identity

CRDs are generated to `charts/region/crds/` via controller-gen.

#### OpenAPI Specification (`pkg/openapi/`)
- `server.spec.yaml`: Source of truth for REST API
- Generated files: `types.go`, `client.go`, `router.go`, `schema.go`
- Uses oapi-codegen v2.4.1 with chi-server framework

### Key Patterns

#### Region Provider Selection
Regions define cloud providers via the `Provider` enum (`openstack`, `kubernetes`). The provider factory (`pkg/providers/providers.go`) instantiates the correct implementation based on `Region.Spec.Provider`.

#### Security Model
The service holds elevated credentials to multiple clouds, making it a security-sensitive component. Future architecture will move to platform-specific region controllers to limit blast radius. Current security features:
- OIDC-based authentication
- RBAC via identity service integration
- Namespace isolation for multi-tenancy

#### Resource Reconciliation
Controllers use controller-runtime's reconciliation loop pattern. Each controller watches specific CRD types and reconciles actual state to desired state defined in the CRD spec.

#### API Authentication
REST API uses OAuth2 authentication (`oauth2Authentication` security scheme) validated against the identity service specified in configuration.

## Configuration

### Environment Variables
Server configuration is defined in `pkg/server/options.go` and controller-specific option files. Key settings include:
- Namespace for region resources
- OIDC issuer endpoints
- OpenTelemetry configuration
- Provider-specific settings

### Helm Values
Chart configuration in `charts/region/values.yaml`:
- Image repositories and tags
- Ingress configuration
- Region definitions with provider configs
- Service account secrets for cloud credentials

## Dependencies

- **Go 1.24.2**: Language runtime
- **Kubernetes**: v0.33.1 (client-go, api, apimachinery)
- **controller-runtime**: v0.20.4 for Kubernetes controllers
- **OpenAPI/oapi-codegen**: v2.4.1 for API code generation
- **Chi**: v5.2.2 HTTP router
- **Gophercloud**: v2.10.0 for OpenStack integration
- **OpenTelemetry**: v1.35.0 for observability
- **Ginkgo/Gomega**: v2.22.0/v1.36.1 for testing

## Common Workflows

### Adding a New API Endpoint
1. Modify `pkg/openapi/server.spec.yaml` to add endpoint definition
2. Run `make pkg/openapi/types.go pkg/openapi/client.go pkg/openapi/router.go` to regenerate
3. Implement handler method in appropriate `pkg/handler/*` file
4. Add RBAC checks using identity client
5. Run `make test-unit` and `make lint`

### Adding a New Provider
1. Create directory under `pkg/providers/internal/<provider-name>/`
2. Implement `types.Provider` interface
3. Add provider type to `pkg/apis/unikorn/v1alpha1/types.go` Provider enum
4. Update provider factory in `pkg/providers/providers.go`
5. Add provider-specific spec to `RegionSpec` in CRD types
6. Run `make $(GENDIR) $(CRDDIR)` to regenerate code and CRDs

### Modifying Custom Resources
1. Edit types in `pkg/apis/unikorn/v1alpha1/types.go`
2. Run `make $(GENDIR)` to regenerate deepcopy methods
3. Run `make $(CRDDIR)` to regenerate CRDs
4. Update Helm chart if needed
5. Run `make test-unit` to verify

### Working with Multiple Controllers
Each controller is a separate binary but shares common code (API types, providers, clients). When modifying shared code, rebuild all affected controllers:
```bash
# Rebuild all controllers
make

# Or rebuild specific ones
make bin/$(go env GOARCH)-linux-gnu/unikorn-region-controller
```

## Provider-Specific Notes

### OpenStack Provider
Requires OpenStack credentials secret with keys: `domain-id`, `project-id`, `user-id`, `password`. See `pkg/providers/internal/openstack/README.md` for detailed setup including custom policies and domain configuration.

### Kubernetes Provider
Requires kubeconfig secret and node flavor metadata. Nodes must have `kubernetes.region.unikorn-cloud.org/node-class` labels. See `pkg/providers/internal/kubernetes/README.md` for prerequisites including ingress-nginx, external-dns, and Prometheus.

## Important Files

- `Makefile`: Build system and all development commands
- `go.mod`: Go module dependencies
- `pkg/openapi/server.spec.yaml`: API specification (source of truth)
- `pkg/apis/unikorn/v1alpha1/types.go`: Custom resource definitions
- `charts/region/crds/`: Generated Kubernetes CRDs
- `pkg/constants/constants.go`: Application constants and version info
- `pkg/providers/providers.go`: Provider factory and caching
- `pkg/handler/handler.go`: Main API handler orchestration
