# Test strategy

## Obiettivi

- Ogni requisito di sicurezza ha test e acceptance evidence.
- Tutti i servizi esterni sono simulabili con fixture sintetiche.
- I confini Windows vengono testati su host reali, non solo con mock.
- Le negative path sono first-class test.

## Livelli

### Unit

- DPAPI provider con abstraction e Windows-only suite.
- AES-GCM envelope, AAD, nonce, corruption e key rotation.
- Redaction strutturale e exception sanitizer.
- Application authorization e grant evaluation.
- RFC 8785 canonicalization/checksum.
- Connector JSON Schema e semantic/security validator.
- Endpoint/path/header allowlist e SSRF IP classifier.
- OAuth, HMAC, JWT claim constraints e session lifecycle.
- XML parser, schema, canonicalization e wrapping defenses.
- Lifecycle/versioning/rollback state machine.

### Integration

- Named Pipe framing, concurrent request, cancellation e limits.
- Windows service sotto virtual account.
- Pipe/ProgramData/CNG ACL.
- Same-user process non autorizzato.
- Authorized publisher/path e invalid hash.
- PostgreSQL 18 tramite Testcontainers, migration e RLS.
- Enrollment/renewal/revocation e request signature.
- Azure Key Vault mocked provider e reale test Vault.
- Container health/readiness e graceful shutdown.
- Connector publish/cache invalidation/rollback.

### End-to-end obbligatori

1. SOAP + Basic.
2. SOAP + Basic + session token.
3. REST + OAuth client credentials.
4. Authorization code acquisito localmente e scambiato centralmente.
5. mTLS centralizzato.
6. HMAC calcolato dal Local Broker.
7. JWT firmato dal Gateway.
8. Certificato Tenant locale.
9. Connector/operation non autorizzata.
10. Tentativo cross-Tenant.
11. URL/redirect/DNS SSRF.
12. Token in input, error e log con verifica di assenza.
13. Rollback ConnectorVersion.
14. Installation revocata.
15. Vault indisponibile/throttled.

Ogni scenario usa mock server controllabile per timeout, TLS, redirect, malformed response e decompression bomb.

### Security

- Fuzzing frame IPC, control JSON, request JSON e XML.
- Oversize, depth/nodes/property count e slow client.
- Path traversal e ambiguous encoding.
- SSRF IPv4/IPv6, loopback, RFC1918, link-local, metadata e DNS rebinding.
- Header injection/smuggling e hop-by-hop header.
- XXE, entity expansion e signature wrapping.
- Replay timestamp/nonce e idempotency conflict.
- Pipe ACL, process identity e PID reuse simulation.
- Secret scanning, SAST, dependency e container scanning.
- Plugin package signature/publisher/tamper test.

### Compatibility

- Windows 11 e Server 2019/2022/2025.
- Windows 10 ESU compatibility job separato.
- MSI install, repair, upgrade, rollback e uninstall.
- SDK .NET su .NET Framework 4.7.2+ e .NET moderno.
- C ABI e COM x86/x64.
- Sample VB6/Delphi/C/COBOL-compatible calling convention.
- Unicode, binary buffer e large payload.

### UI

Playwright:

- Entra test identity/role mapping;
- Viewer read-only;
- editor non pubblica;
- autore non approva il proprio draft;
- published immutabile;
- rollback e audit;
- nessun valore Vault nell'HTML/API/browser log.

### Performance e resilienza

- 50 RPS sostenuti e 100 concurrent per istanza.
- 10.000 Installation nel registry.
- warm/cold Vault cache.
- payload 16 MiB e stream 64 MiB con backpressure.
- PostgreSQL failover/reconnect.
- external timeout, retry e circuit breaker isolation.
- cache invalidation e polling fallback.

## CI matrix

| Job | Runner |
|---|---|
| format/analyzers/unit/schema | Linux |
| Gateway integration/container | Linux + Docker |
| Broker/ACL/service/MSI | Windows Server |
| native/COM x86/x64 | Windows |
| E2E/security | Linux + Windows client |
| SBOM/scanning/signature synthetic | Linux/Windows |

I test che richiedono Azure reale usano un Environment test isolato e sono schedulati/pre-release, non dipendenza di ogni commit.

## Fixture policy

- Solo domini `example.invalid` e certificati generati per test.
- Identità e payload sintetici marcati chiaramente.
- Nessun snapshot contenente request/response reali.
- Secret scanner eseguito anche su test result e package staging.

## Acceptance evidence

Ogni test produce ID stabile e viene referenziato da `docs/traceability/requirements-traceability.md`. La release pipeline allega report test, scan, SBOM, artifact hash e signature verification al release manifest.

