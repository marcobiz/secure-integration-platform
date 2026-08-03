# ADR-0013: Deployment Azure

**Stato:** Accepted

## Decisione

Linux Azure App Service for Containers, ACR, Key Vault, PostgreSQL Flexible Server, Managed Identity, Application Insights/Log Analytics e Bicep. Ambienti isolati dev/test/preprod/prod.

## Conseguenze

Operations inferiori ad AKS e supporto mTLS con certificate forwarding. Il Gateway valida sempre il certificato inoltrato. VNet e firewall sono baseline; Private Endpoint/WAF sono profili attivabili.

## Alternative escluse

AKS, Container Apps e App Service Windows non offrono vantaggio sufficiente per l'MVP; Terraform non viene mantenuto in parallelo a Bicep.

