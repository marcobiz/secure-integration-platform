# ADR-0007: Azure Key Vault

**Stato:** Accepted

## Decisione

Azure Key Vault è il provider produttivo iniziale del deployment pack Azure. Il pack usa Managed Identity; il database conserva solo riferimenti logici/provider. Come stabilito da ADR-0019, il Core espone capability separate (`ISecretValueProvider`, `IClientCertificateProvider`, signing, MAC e health) e non contiene pacchetti o tipi Azure.

## Conseguenze

Rotazione e access audit sono centralizzati. Latenza/throttling richiedono cache in memoria breve. Self-hosted deve procurarsi un'identità Azure esterna al repository.

## Alternative escluse

AWS Secrets Manager e HashiCorp Vault restano future opzioni; secret cifrati in PostgreSQL violerebbero l'invariante del prodotto.
