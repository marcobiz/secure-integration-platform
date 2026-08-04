# M2 — Piano implementativo del Gateway minimo

**Stato:** implementazione e PostgreSQL 18 locale completati; container/CI pendente
**Baseline:** `d1113d34a18e166c9eb0c14d8e11c3c1a1a20c12`
**Gate precedente:** M0/M1 PASS-LIVE, AC-002 e AC-004 PASS-LIVE

## Obiettivo e perimetro

M2 introduce un Gateway modular monolith eseguibile che assegna a ogni Installation
un'identità distinta, deriva sempre il Tenant dall'identità autenticata e consente
soltanto invocazioni verso operation configurate dal server. Il Gateway usa PostgreSQL
come source of truth, Azure Key Vault come provider produttivo e un provider sintetico
esclusivamente nei test.

Sono inclusi:

- host ASP.NET Core con health/readiness e Problem Details redatti;
- registry Tenant/Application/Environment/Installation e grant;
- migrazione PostgreSQL 18 esplicita, composite FK, ruoli e RLS `FORCE`;
- activation code monouso, challenge breve e proof-of-possession ECDSA P-256;
- registrazione, rinnovo con overlap e revoca della credential Installation;
- autenticazione runtime con certificato ClientAuth, firma envelope, timestamp,
  digest e nonce anti-replay;
- catalogo operation configurato esclusivamente sul server;
- provider Azure Key Vault tramite Managed Identity e provider sintetico con guard;
- egress HTTPS ristretto, host/path/method/header fissati, redirect/proxy disabilitati,
  limiti, timeout e Basic/API key/mTLS centralizzati;
- audit metadata-only e correlation W3C;
- Dockerfile non-root con health check;
- test unit, integration, security e PostgreSQL 18 reale in CI.

Non sono inclusi:

- lifecycle/versioning/publish/rollback dei Connector (M4);
- Admin UI, Entra OIDC e four-eyes (M5);
- adapter COM/C ABI/CLI (M6);
- OAuth/JWT/SOAP e moduli di autenticazione estesi (M7);
- il nuovo vertical slice Broker→Gateway→Vault→mock, che resta il gate M3;
- CA enterprise, recovery/rotation operativa completa e deployment Azure completo (M9).

Per M2 le operation sono configurazione di startup immutabile. Non sono ConnectorVersion
e non anticipano lo state machine M4.

## Incrementi compilabili

1. **Gateway foundation:** progetti Domain/Application/Infrastructure/API e test;
   contratti, error model, clock e repository in-memory.
2. **Persistence:** migrazione SQL, repository Npgsql, tenant context transaction-local,
   RLS e test PostgreSQL reali.
3. **Enrollment:** activation hash HMAC, challenge TTL, certificato ClientAuth e PoP,
   rinnovo, overlap e revoca.
4. **Runtime identity:** estrazione certificato, lookup registry, Tenant server-side,
   body hash, canonical signing input, timestamp e nonce replay.
5. **Vault ed egress:** Key Vault/Managed Identity, synthetic guard, operation catalog,
   Basic/API key/mTLS e trasporto ristretto.
6. **Hosting/package:** endpoint OpenAPI M2, health/readiness, Dockerfile e runbook.
7. **Gate:** build, test, PostgreSQL CI, secret/dependency scan, traceability e stato.

Ogni incremento deve lasciare `eng/build.ps1` e `eng/test.ps1` verdi.

## Tracciabilità M2

| Requisito | Evidenza prevista |
|---|---|
| FR-001 | `IT_DAT_PostgreSQL18_registry_enrollment_grant_replay_and_revocation_when_configured` |
| FR-002 | `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected`, renewal e revocation tests |
| FR-007 / AC-011 | `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected` |
| AC-012 | `UT_GTW_Cross_tenant_grant_is_rejected`; `IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured` |
| AC-013 | `UT_GTW_Revocation_is_immediate_for_runtime_and_grants`; E2E completo nel gate M3 |
| AC-007/009/010 | invoke-contract, fixed endpoint, Basic/API key/mTLS e deny-before-side-effect tests |
| FR-016 / NFR-001 | `UT_SEC_Audit_is_metadata_only_and_excludes_payload_and_credentials`; API log/Problem canary tests |
| NFR-002/003 | SSRF/private IP, catalog HTTPS, DNS pinning e TLS configuration tests/review |
| NFR-005 | `UT_EGR_Transient_retry_occurs_only_for_idempotent_operation` |
| NFR-006 | correlation ID firmato/auditato; `traceparent` richiesto dall'endpoint invoke |
| AC-018 | container build/smoke in CI con health endpoint |

## PostgreSQL e ambiente di test

L'HOST corrente non dispone di Docker/Podman né di un'istanza PostgreSQL attiva. È stata
però usata l'installazione binaria PostgreSQL 18 già presente per avviare un cluster
effimero non privilegiato sotto `.artifacts`; la suite reale richiede
`GATEWAY_POSTGRES_ADMIN_CONNECTION`.
GitHub Actions avvia PostgreSQL 18 come service container, applica la migrazione da zero
e verifica CRUD, composite FK, `SET LOCAL app.tenant_id`, RLS cross-Tenant e replay nonce.
Il test locale PostgreSQL 18 è PASS; un risultato CI/container mancante non può chiudere
il gate M2.

## Invarianti di sicurezza

- Activation code memorizzato soltanto come HMAC; challenge e nonce hanno TTL.
- Il certificato presentato deve corrispondere a SPKI/certificate hash registrati.
- La firma copre method, path/query normalizzati, timestamp, nonce e body esatto.
- Tenant, endpoint, method, header sensibili e secret reference non provengono dal client.
- Il database non conserva secret value o response body.
- Il provider sintetico fallisce all'avvio fuori da Development/Testing.
- Egress è HTTPS, senza redirect/proxy, con DNS/IP filtering e limiti espliciti.
- Log, Problem Details e audit non contengono body, credential, vault reference o header.
- Revoca e replay sono controllati prima di qualsiasi accesso Vault/egress.

## Criterio di completamento

M2 è Done solo quando build e test locali sono verdi, la suite PostgreSQL 18 e il
container smoke passano in CI, secret/vulnerability scan sono verdi, la documentazione
e la matrice di tracciabilità riportano nomi di test reali e non resta alcun bypass
nel perimetro dichiarato. L'assenza di credenziali Azure autorizza test con mock del
client SDK ma non la dichiarazione di una prova live Key Vault.
