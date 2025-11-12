# File Storage Providers

Providers are responsible for all operations required to reconcile a FileStorage resource from its desired state to the actual state. A provider encapsulates the control logic and any external integrations necessary to provision, update, and delete file storages in a specific environment.

A provider must implement the `Provider` interface. This guarantees a consistent contract across different implementations and allows the system to plug in new providers without changing the reconciliation logic outside the provider boundary.

Core responsibilities of a provider include (non-exhaustive):
- Observing current state and comparing it with the desired specification.
- Creating, updating, and deleting file storages in an idempotent manner.
- Handling provider-specific communication, authentication, and error handling.
- Reporting status and surfacing meaningful errors for diagnostics.
- Being safe to call repeatedly (level-based reconciliation).

## Supported Providers

| Name  | Type         | Transport                | Notes                                    |
|-------|--------------|--------------------------|------------------------------------------|
| Agent | Remote agent | NATS (initial support)   | Designed for air-gapped/controlled envs. |

As more providers are added, extend this table with their capabilities and transport details.

## Agent Provider

The Agent provider manages file storages through remote agents. It is designed for environments where storage management must occur within restricted or air-gapped networks.

Key characteristics:
- Control Plane <-> Agent model: reconciliation requests are executed by agents running close to the storage systems.
- Initial communication protocol: NATS for request/response and eventing.
- Extensible transport: the design can be extended to support other transports such as TCP or WebSocket as needed by the deployment environment.
- Suitable for air-gapped or restricted environments where direct control plane access to storage backends is not possible.

Implementation notes:
- The provider must implement the `Provider` interface defined in this package.
- Transports should be pluggable to allow adding non-NATS mechanisms without changing the provider’s external contract.
- Ensure operations are idempotent to handle retries and disconnected scenarios typical of air-gapped deployments.
