# ADR-0011: Secure Layer and Managed Connector

**Status:** Accepted

## Decision

Each integration starts in Secure Layer mode unless there is a demonstrated benefit otherwise. Use Managed Connector when the protocol is reused, changes frequently or benefits from centralized maintenance. Both modes share grants, egress and binding.

## Consequences

Initial migration requires minimal changes. The legacy application can keep building payloads, but does not choose endpoints or secrets. Extraction into Managed mode does not change the security contract.
