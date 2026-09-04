# Assumptions, defaults and external dependencies

## Technical defaults

- .NET 10 LTS for Local Broker, Gateway and Admin.
- C++20 for C ABI and COM Automation x86/x64.
- PostgreSQL 18 as the operational database.
- Azure App Service for Containers, Azure Key Vault, Managed Identity, Azure Database for PostgreSQL Flexible Server and Bicep.
- Windows 11 and Windows Server 2019/2022/2025 as baseline; Windows 10 22H2 only in the compatibility tier with ESU.
- GitHub Actions as the reference pipeline, with scripts also executable locally and no lock-in in build logic.
- REST Secure Layer with vendor API key and mTLS as the first synthetic vertical slice.
- RFC 8785 canonical JSON and JSON Schema Draft 2020-12.

## Initial targets, not contractual SLAs

- 50 sustained requests/second per Gateway instance.
- 100 concurrent requests per instance.
- 10,000 Installations in the registry scale test.
- Maximum ordinary payload 16 MiB; maximum streaming 64 MiB.
- Default outbound timeout 30 seconds, maximum 60.
- MVP availability target 99.9%.
- Operational audit retention 90 days and administrative retention 365 days.

## Nonblocking decisions before the pilot

M0–M7 development and synthetic Connectors do not depend on:

- real credentials or certificates;
- access to production healthcare services;
- final pilot legacy product;
- final Azure region;
- final commercial volumes.

## Inputs needed before the real pilot

- formally selected product and integration;
- external-service contracts and test environment;
- Windows matrix of the installed base;
- Entra Tenant, Azure region and data-residency requirements;
- code-signing certificate ownership and custody;
- authorized process for revoking and rotating old secrets;
- contractual SLOs, volumes, retention and DR requirements.

Without these inputs, the documented defaults are used without blocking the synthetic vertical slice.
