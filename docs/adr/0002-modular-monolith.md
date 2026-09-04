# ADR-0002: Gateway modular monolith

**Status:** Accepted

## Context

The platform needs runtime, enrollment, configuration, administration and audit, but there are no workloads or teams yet that justify microservices.

## Decision

A single Gateway process and image, with separate Domain/Application/Infrastructure modules and controlled dependencies. A single operational PostgreSQL database.

## Consequences

Deployment, transactions and development remain simple. Modular boundaries allow future extraction based on evidence. A process failure affects all modules and requires effective health checks.

## Rejected alternatives

Microservices, a service mesh and message brokers are not justified in the MVP.
