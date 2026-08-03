# Piano di implementazione

## Strategia

Implementare vertical slice piccoli mantenendo il repository compilabile. Ogni milestone produce artefatti installabili/testabili; i servizi esterni sono mock finché non sono disponibili accessi autorizzati.

Un containment track esterno parte in parallelo: rotazione dei segreti noti, TLS validation, log redaction, ACL, chiusura porte e rimozione HTTP/FTP. Non dipende dal completamento della piattaforma.

## M0 — Repository e fondamenta

**Obiettivo:** monorepo riproducibile e security gates attivi.

**Task:** inizializzare Git/solution; central package management; analyzers; build/test scripts; GitHub Actions; secret/dependency/container scanning; SBOM; ADR/doc checks; Docker/MSI skeleton.

**Dipendenze:** nessuna.

**Test:** clean clone build, unit placeholder, schema parse, secret scan, SBOM generation.

**Completamento:** build locale=CI, toolchain pinned, nessun secret, release manifest sintetico.

**Rischi:** licensing tool e runner Windows.

**Artefatti:** repository, pipeline, conventions, unsigned skeleton packages.

## M1 — Local Broker minimo

**Obiettivo:** boundary locale reale su Windows.

**Task:** service/virtual account; ProgramData/ACL; Named Pipe/framing; caller identity; Application manifest; DPAPI; AES-GCM; Put/DeleteLocalSecret; Protect/UnprotectData; ComputeHmac; status; SDK .NET.

**Dipendenze:** M0, IPC contract v1.

**Test:** service account, pipe ACL, same-user unauthorized process, offline storage copy, corruption, key version, concurrency/cancellation.

**Completamento:** processo autorizzato usa le operation; processo non autorizzato è negato; nessun plaintext a riposo.

**Rischi:** DPAPI CurrentUser/profile e process identification su versioni Windows.

**Artefatti:** Broker service, SDK, simulator, Windows integration suite.

## M2 — Gateway minimo

**Obiettivo:** identità Installation e invocazione centrale sicura.

**Task:** Gateway host; PostgreSQL/migrations/RLS; Tenant/Application/Installation; activation/challenge/PoP; mTLS/signature/replay; revocation; Azure Key Vault; Basic/API key/mTLS; restricted egress; Docker.

**Dipendenze:** M0 e identity portion M1.

**Test:** enrollment, clone/replay, cross-Tenant, revoked credential, Vault unavailable, SSRF/TLS/limits.

**Completamento:** ogni request deriva Tenant dal certificato e non accetta URL/secret client-controlled.

**Rischi:** certificate forwarding App Service e Vault latency.

**Artefatti:** container, DB schema, OpenAPI implementation e Bicep skeleton.

## M3 — Primo vertical slice

**Obiettivo:** prova end-to-end senza GetSecret.

**Scenario:** legacy simulator → Broker → Gateway → Vault synthetic provider/test Vault → mock REST; API key vendor e mTLS applicati centralmente; body JSON pre-costruito.

**Dipendenze:** M1-M2.

**Test:** success, invalid grant, secret absent, TLS failure, timeout, replay, log redaction.

**Completamento:** Vendor Secret non compare su client/DB/log e il client non cambia endpoint.

**Artefatti:** runnable demo tecnica, E2E report e sample Secure Layer.

## M4 — Connector configuration

**Obiettivo:** configuration plane versionato.

**Task:** JSON Schema/semantic/security validation; canonical JSON; lifecycle; SecretBinding; grants; deployment revision; cache invalidation; promotion; rollback; plugin manifest validation.

**Dipendenze:** M2-M3.

**Test:** invalid schema/security, immutabilità Published, author≠approver, atomic rollback, stale cache fallback.

**Completamento:** runtime usa soltanto versioni Published; rollback senza restart.

**Artefatti:** validator CLI/Admin API, schemas ed export/import.

## M5 — Admin UI

**Obiettivo:** amministrazione sicura senza accesso ai valori Vault.

**Task:** Entra OIDC; app roles; Tenant/Application/Installation; enrollment/revocation; editor JSON; validation; four-eyes; publish/rollback; binding metadata; audit; health.

**Dipendenze:** M4.

**Test:** Playwright RBAC/four-eyes/immutabilità, CSRF, secret absence nel browser.

**Completamento:** tutte le operazioni amministrative hanno policy e audit.

**Artefatti:** Admin Web e runbook amministrativo.

## M6 — Adapter legacy

**Obiettivo:** interoperabilità non-.NET.

**Task:** C++ client/framing; C ABI; COM Automation; CLI stdin; x86/x64; sample VB6/Delphi/C; packaging.

**Dipendenze:** IPC v1 congelato e M1 stabile.

**Test:** buffer, Unicode/binary, timeout, cancellation, thread safety, install/upgrade.

**Completamento:** sample x86/x64 invocano lo stesso Broker senza secret negli adapter.

**Artefatti:** DLL/COM/CLI, header/type library e samples.

## M7 — Authentication modules

**Obiettivo:** coprire i protocolli ricorrenti.

**Task:** OAuth client credentials; authorization code; PKCE; session refs; JWT RS256; local certificate; SOAP/XML; HMAC policies; token rotation/refresh.

**Dipendenze:** M3-M4.

**Test:** E2E dedicato per ogni modulo, claim/algorithm confusion, token redaction, XML attacks.

**Completamento:** auth params e key sono fissati dal Connector, non dal client.

**Artefatti:** built-in adapters e test pack.

## M8 — Healthcare Connector Pack e pilot

**Obiettivo:** dimostrare Secure Layer e Managed Connector sanitari.

**Task:** Secure Layer sintetico vendor mTLS; Managed SOAP Basic+session; provenance; Connector Pack signing; selezione seam prodotto pilota; migrazione/rotation/egress removal.

**Dipendenze:** M5-M7; input esterni solo per la parte reale.

**Test:** characterization, E2E, regression, security e rollback.

**Completamento:** nel pilot reale AC-029/030 e acceptance pack firmato.

**Artefatti:** Healthcare Pack, Integration Seam Map e pilot report.

## M9 — Hardening enterprise

**Obiettivo:** release installabile e operabile enterprise.

**Task:** signing production; secure updater/anti-rollback; MSI hardening; container signing; HA/DR; backup restore; rotation/recovery; penetration test; operational/security documentation.

**Dipendenze:** tutte le milestone precedenti.

**Test:** installer matrix, signature/tamper, restore/failover, recovery ceremony, load/resilience e pentest remediation.

**Completamento:** tutti gli AC globali, SBOM/release manifest, runbook e residual risk acceptance.

**Artefatti:** release pack completo.

## Sequenza critica

```text
M0 → IPC v1 → M1 → M2 → M3 → M4
                       ├→ M5
                       ├→ M6
                       └→ M7
                    M5+M6+M7 → M8 → M9
```

M5, M6 e parte di M7 possono procedere in parallelo dopo la stabilizzazione dei rispettivi contratti.

