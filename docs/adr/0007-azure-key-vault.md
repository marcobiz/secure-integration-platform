# ADR-0007: Azure Key Vault

**Status:** Accepted

## Decision

Azure Key Vault is the initial production provider for the Azure deployment pack. The pack uses Managed Identity; the database stores only logical/provider references. As established by ADR-0019, Core exposes separate capabilities (`ISecretValueProvider`, `IClientCertificateProvider`, signing, MAC and health) and contains no Azure packages or types.

## Consequences

Rotation and access audit are centralized. Latency/throttling require a short-lived in-memory cache. Self-hosted deployments must obtain an Azure identity outside the repository.

## Rejected alternatives

AWS Secrets Manager and HashiCorp Vault remain future options; encrypted secrets in PostgreSQL would violate the product invariant.
