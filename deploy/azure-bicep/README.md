# Azure Bicep deployment

`main.bicep` remains the non-deploying M2 contract. `m3-dev.bicep` is the executable,
ephemeral M3B smoke environment and must be deployed only from the protected GitHub
Environment `azure-dev` using OIDC.

M3B creates ACR, a user-assigned Gateway identity, Linux App Service containers, Key
Vault RBAC, PostgreSQL Flexible Server 18, Log Analytics and Application Insights. The
Gateway identity has ACR pull and Key Vault secret-read only; the OIDC deployment
principal has scoped ACR push and synthetic secret provisioning. PostgreSQL public
access is a deliberate dev-smoke limitation: the workflow adds its runner IP
temporarily and removes it, while `0.0.0.0` permits Azure services. Private networking
and production hardening remain M9 and this template must not be promoted as-is.

The template accepts only synthetic secure parameters and immutable image references.
No Azure client secret, certificate private key, database password or vendor value is
stored in this directory.
