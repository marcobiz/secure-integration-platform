# ADR-0019: Physical provider-pack boundaries

**Status:** Accepted

## Context

M4 Core contained Azure types and packages in `Gateway.Infrastructure` and the composition root. Separation was logical but insufficient to demonstrate that the open-source product could build, be tested and be distributed without Azure.

## Decision

- Capabilities are narrow, separate contracts: secret value retrieval, certificate retrieval, signing/key use, MAC, health and capability discovery. There is no generic `IKms`.
- Contracts live in `src/Providers/Abstractions` and do not depend on cloud SDKs.
- The synthetic provider lives in `src/Providers/Synthetic` and is part of the locally testable Core.
- Deployment-specific providers live under `packs/deployment/<provider>` and depend on Core, never the reverse.
- The Gateway loads an optional pack through a provider-neutral contract and explicit configuration. Provider types, URI schemes, credential classes and SDKs do not cross the Core boundary.
- A Core solution, an architecture test and the OSS export verify the absence of provider-specific references.
- The Azure pack is optional and remains excluded from the OSS export until the publication/licensing strategy is decided.

## Consequences

Core builds without Azure packages and can use the synthetic provider for CI and quickstart. A deployment pack retains ownership of cloud authentication, parsing its own references and provider-specific health. Deployment-specific assembly requires explicit packaging and cannot be achieved by adding Azure conditions in the Core composition root.

## Rejected alternatives

- A generic `IKms` interface, because it hides capabilities and broadens privileges.
- Conditional Azure references in the Core project, because they do not demonstrate physical independence.
- `#if AZURE`, reflection on Azure types in the composition root or automatic fallbacks, because they make the boundary ambiguous and not fail-closed.
