# ADR-0015: Local, central and hybrid execution

**Status:** Accepted

## Decision

Each operation declares `gateway`, `broker` or `hybrid`. `hybrid` allows only typed handoffs: authorization-code exchange, local signature or local MFA.

## Consequences

A Vendor Secret requires Gateway execution; smart cards, VPNs and non-exportable keys require Broker execution. The client cannot change the location. Additional hybrid flows require an ADR and threat analysis.
