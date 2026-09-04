# ADR-0013: Azure deployment

**Status:** Accepted

## Decision

Linux Azure App Service for Containers, ACR, Key Vault, PostgreSQL Flexible Server, Managed Identity, Application Insights/Log Analytics and Bicep. Isolated dev/test/preprod/prod environments.

## Consequences

Less operational work than AKS and mTLS support through certificate forwarding. The Gateway always validates the forwarded certificate. VNet and firewall are baseline controls; Private Endpoint/WAF are optional profiles.

## Rejected alternatives

AKS, Container Apps and Windows App Service offer insufficient benefit for the MVP; Terraform is not maintained alongside Bicep.
