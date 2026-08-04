# Azure Bicep deployment contract (M2 skeleton)

This directory intentionally contains only the M2 deployment contract: environment,
region and immutable image digest. It creates no Azure resource.

`DEP-02`/M9 will add the App Service, ACR, Key Vault, PostgreSQL, private networking and
observability modules described by ADR-0013. Keeping the M2 file non-deploying avoids
shipping an incomplete or insecure cloud topology while preserving a Bicep entry point
for pipeline validation.
