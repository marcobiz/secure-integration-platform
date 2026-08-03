# ADR-0007: Azure Key Vault

**Stato:** Accepted

## Decisione

Azure Key Vault è l'unico Vault produttivo iniziale. Il Gateway usa Managed Identity; il database conserva solo riferimenti logici/provider. `ISecretProvider` consente sostituzione futura senza implementare provider non richiesti.

## Conseguenze

Rotazione e access audit sono centralizzati. Latenza/throttling richiedono cache in memoria breve. Self-hosted deve procurarsi un'identità Azure esterna al repository.

## Alternative escluse

AWS Secrets Manager e HashiCorp Vault restano future opzioni; secret cifrati in PostgreSQL violerebbero l'invariante del prodotto.

