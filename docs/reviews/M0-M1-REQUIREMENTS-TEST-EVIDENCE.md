# Matrice M0/M1: requisito → test → evidenza

Data review: 2026-08-03. Baseline esaminata: commit `7f68442ceb9adcc47bb1b1a534ad64e23bd26bac`, tag `baseline-m0-m1-vslice-2026-08-03`. La run live usa SUT baseline `39ac4eae23d6a4c43729863ca345fdbf10af0ee6`, harness baseline `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170` e commit testato `24288dbe065ecedc21c0018e8ed37ca844bc8caf`.

## Legenda

- **PASS-A**: test automatico eseguito in questa review.
- **PASS-C**: evidenza ottenuta da checkout pulito del tag baseline.
- **PASS-S**: verifica statica o gate di repository; non sostituisce una prova live.
- **PASS-LIVE**: prova completata su Windows Service reale con identità distinte e reboot.
- **PARZIALE**: una parte è automatizzata, ma manca l'evidenza richiesta.
- **OPEN-LIVE**: richiede ancora una prova live completa.
- **OUT**: appartiene esplicitamente a milestone successive.

I nomi sotto sono nomi test reali, non ID pianificati.

## M0 — fondamenta

| Gate M0 | Evidenza precisa | Stato | Limite |
|---|---|---|---|
| Git e baseline identificabile | commit `7f68442`; tag annotato `baseline-m0-m1-vslice-2026-08-03` | PASS-S | Tag locale; nessun remote configurato/verificato. |
| Toolchain pinned | `global.json` = SDK 10.0.302; clean checkout compilato con SDK 10.0.302 esterno al clone | PASS-C | Lo script non installa autonomamente l'SDK. |
| Restore/build riproducibile | `eng/build.ps1`; clean checkout del tag: build Release, 0 warning/0 errori | PASS-C | Eseguito sullo stesso host, non su OS pulito. |
| Test runner e solution | `eng/test.ps1`; clean checkout del tag: 6 unit + 9 integration + 1 E2E | PASS-C | Il tag precede gli hardening test aggiunti dalla review. |
| Analyzer/warnings | build Release con `TreatWarningsAsErrors` | PASS-A | Non sostituisce SAST dedicato. |
| Schema/documentazione | `eng/validate-docs.ps1` | PASS-A | Validator mirato a JSON e link previsti, non Markdown lint completo. |
| Secret scan | `eng/scan-secrets.ps1`; pattern scan + gitleaks definito in CI | PASS-A/PASS-S | Gitleaks CI non eseguito in questa sessione. Durante la review è stato corretto l'exit code spurio del wrapper PowerShell. |
| Dependency vulnerability | `dotnet list BrokerGateway.slnx package --vulnerable --include-transitive` | PASS-A | Snapshot delle feed alla data review. |
| SBOM | `eng/generate-sbom.ps1`, SPDX 2.2 generato | PASS-A | Artefatto in `.artifacts`, non firmato. |
| CI | `.github/workflows/ci.yml` ispezionato | PASS-S | Nessuna run GitHub Actions disponibile: requisito non ancora automatizzato su remote. |
| Skeleton package | `deploy/windows`, `deploy/docker`, release manifest | PASS-S | MSI/container reali sono milestone successive. |

## M1 — requisiti funzionali

| Requisito | Test/evidenza eseguita | Stato | Non ancora dimostrato |
|---|---|---|---|
| FR-003 — autorizzazione Application/operation | test automatici più matrice live A-C con processo stesso utente non autorizzato e altro utente | PASS-A/PASS-LIVE | Publisher Authenticode ha solo negative path su binario unsigned. |
| FR-004 — Put/Delete senza GetSecret | test automatici più lifecycle live attraverso servizio installato, restart e reboot | PASS-A/PASS-LIVE | Nessun gap M1 residuo. |
| FR-005 — AEAD/key versioning | `UT_CRYPTO_AeadRoundTripTamperRotation`; `AES_GCM_nonce_is_unique_across_repeated_protection`; `AEAD_authenticates_application_purpose_and_content_type`; `AEAD_rejects_unknown_key_version_without_trying_another_key`; `AEAD_rejects_malformed_envelope`; `AC005_Installation_key_and_ciphertext_differentiation` | PASS-A | Rotazione operativa/atomica non implementata. |
| FR-006 — HMAC M1 | `UT_BRK_LocalSecretLifecycle`; `HMAC_requires_an_explicit_secret_operation_grant`; `Repository_reopen_recovers_keys_secrets_and_protected_data_under_same_identity` | PASS-A | Firma e certificato locale: OUT (M7). |
| FR-015 — SDK .NET, porzione M1 | SDK usato da `IT_BRK_*`, concurrency e vertical slice E2E; build `netstandard2.0`/`net10.0` | PASS-A | .NET Framework/COM/C ABI/CLI: OUT (M6); IPC non congelato. |
| FR-018 — operazioni locali offline | test automatici più DPAPI sotto virtual service account, restart SCM e reboot reale | PASS-A/PASS-LIVE | Recovery operativa del profilo resta debito pre-pilot. |

## M1 — requisiti non funzionali e superfici mirate

| Requisito/superficie | Test/evidenza eseguita | Stato | Gap esplicito |
|---|---|---|---|
| NFR-001 — secret/log redaction | test automatici, Event Log reale e scansione live di 11 canary | PASS-A/PASS-LIVE | Crash non gestiti e telemetry futura restano debito. |
| NFR-002 — deny-by-default | negative path automatici più processo same-user e SID differente reali | PASS-A/PASS-LIVE | Nessun gap M1 residuo. |
| NFR-004 — limiti IPC | `IPC_frame_accepts_exact_hard_limit`; `IPC_frame_rejects_body_above_hard_limit`; malformed/truncated/header tests | PARZIALE | Aggregate 16 MiB e stream 64 MiB non assemblati dall'SDK/server. |
| NFR-005 — timeout/cancel/idempotenza | `Pipe_supports_concurrent_clients_and_deadline_cancellation`; `Same_connection_multiplexes_requests_and_honors_cancel_frame`; delete idempotente; stress 20× sui critical IPC tests | PASS-A per M1 | Retry/circuit breaker appartengono a M2+. |
| NFR-006 — correlation | E2E verifica `X-Correlation-Id` Broker→Gateway | PARZIALE | W3C trace context completo non implementato. |
| NFR-008 — build/SBOM | clean checkout, build warning-free, vulnerability scan, SPDX | PASS-A/PASS-C | Firma artefatti non prevista in M0/M1. |
| NFR-010 — no persistence centrale payload | E2E harness mantiene payload solo in memoria; ispezione storage locale | PASS-A nel vertical slice | Nessun Gateway production/DB presente. |
| Framing/version/handshake | `IPC_frame_round_trip_preserves_network_header_and_payload`; hard-limit/malformed/EOF/unknown JSON tests; `Handshake_rejects_nonzero_sequence_and_malformed_nonce` | PASS-A | Fuzzing stateful non eseguito. |
| Multiplexing/cancellation | `Same_connection_multiplexes_requests_and_honors_cancel_frame`; `Pipe_supports_concurrent_clients_and_deadline_cancellation`; stress 20/20 | PASS-A | SDK persistente condiviso non implementato. |
| PID reuse/creation time/handle | `Named_pipe_caller_identity_is_captured_from_the_kernel` verifica PID, path, creation time e chiusura handle processo/file | PARZIALE | PID reuse forzato non è automatizzato; richiede harness/VM dedicato. |
| Race identity→authorization | Code review: process handle e handle read-only dell'eseguibile restano aperti per la connessione; start time ricontrollata; snapshot hash/publisher usato dall'authorizer | PASS-S + test handle | Nessun fault-injection test che sostituisca l'immagine tra capture e authorize. |
| ACL storage | test automatico più ACL exact pre/post reboot con service SID e utenti distinti | PASS-A/PASS-LIVE | Nessun gap M1 residuo. |
| ACL pipe | test automatico più SDDL e access-denied reale per SID differente | PASS-A/PASS-LIVE | Nessun gap M1 residuo. |
| DPAPI CurrentUser | round-trip automatico più negazione cross-identity su blob del servizio | PASS-A/PASS-LIVE | Recovery del profilo service identity resta debito pre-pilot. |
| Nonce AES-GCM | 512 envelope con stessa key/plaintext, nonce 96-bit tutti distinti | PASS-A | Test statistico, non prova matematica del CSPRNG; usa `RandomNumberGenerator`. |
| Metadata AAD | test Application, Installation, purpose e content type errati | PASS-A | Nessun metadata client non previsto è accettato dal JSON. |
| Key versioning/corruzione | rotation/tamper, unknown version, key DPAPI corrotta, secret JSON/base64 corrotto | PASS-A | Scrittura atomica di `active.txt` e comando rotation restano debito. |
| Redazione errori | wire/audit automatici più Event Log live per normal/denied/invalid/crypto/key failure | PASS-A/PASS-LIVE | Crash/unhandled exception e telemetry futura restano debito. |

## Acceptance criteria M0/M1

| AC | Stato gate | Evidenza/nota |
|---|---|---|
| AC-001 | PASS-A per vertical slice | Vendor API key solo nel Gateway harness; assente dal client/Broker/audit. |
| AC-002 | **PASS-LIVE sul commit testato** | Servizio reale su virtual account, restart e persistenza dopo reboot verificati. |
| AC-003 | PASS-A/PASS-LIVE | Policy/hash/publisher/grant e processo same-user realmente distinto verificati. |
| AC-004 | **PASS-LIVE sul commit testato** | ACL pipe/storage e DPAPI cross-identity verificate tra service identity, gestionale e altro utente. |
| AC-005 | PASS-A | Due repository/Installation producono key e ciphertext differenti. |
| AC-006 | PASS-A/PASS-LIVE | Wire/audit e Windows Event Log reale verificati senza leakage dei canary. |
| AC-007 | PASS-A nel harness | Nessun secret nelle response del Gateway harness. |
| AC-008 | PASS-S/PASS-A | Broker dipende solo da `IGatewayInvoker`; nessun provider Vault. |
| AC-009 | PASS-A nel perimetro | Request senza URL, base address HTTPS fissata, TLS negativo. |
| AC-010 | PASS-A nel perimetro | Nessuna secret reference Gateway; grant Connector/operation fisso. |
| AC-020 | PASS-C | Checkout pulito del tag compila e testa con SDK richiesto installato. |
| AC-021 | PASS-A | Vertical slice sintetico ripetibile. |
| AC-023 | PASS-A | Secure Layer E2E. |
| AC-027 | PASS-A | SPDX generato. |

Gli AC non elencati dipendono da M2 o milestone successive e non vengono anticipati.

## Automazione live eseguita

Il pacchetto `tools/live-matrix` è stato eseguito con successo su VM elevata e dopo reboot reale. Il risultato è attribuibile al commit `24288dbe065ecedc21c0018e8ed37ca844bc8caf`.

| Matrice/requisito | Comando/probe reale | Evidenza prodotta dopo PASS |
|---|---|---|
| A / FR-003, FR-004, FR-005, FR-006 | `authorized-pre`, `authorized-post` sotto `SibLiveAuthorized` | status/operation grant, HMAC, Protect/Unprotect e persistence report |
| B / NFR-002 | `unauthorized-same-user`, `storage-denied` dalla copia apphost in path non registrato | connessione DACL riuscita ma handshake policy rifiutato; storage denied |
| C / AC-004 | `unauthorized-other-user`, `storage-denied`, `dpapi-denied` sotto `SibLiveDenied` | pipe/storage denied e CryptUnprotectData fallito |
| D / secret boundary | `read-encrypted-database`, unknown `GetSecret`/`GetDataKey`, HMAC-only secret | DB cifrato leggibile, nessuna API key/secret material |
| E / AC-002, AC-004 | stop/start SCM, `expected-key-failure`, task AtStartup e `authorized-post` | token service SID, tamper rejection, HMAC/envelope validi dopo reboot |
| F / NFR-001, AC-006 | Event Log provider reale e `Invoke-PostReboot.ps1` | normal/denied/invalid/crypto/key failure presenti e canary scan PASS |

<!-- LIVE-MATRIX-AUTOMATION:BEGIN -->
## Ultima matrice live automatizzata

| Campo | Evidenza |
|---|---|
| Run ID | `m0-m1-20260803-232955` |
| Esito | **PASS live A-F** |
| Commit testato | `24288dbe065ecedc21c0018e8ed37ca844bc8caf` |
| Macchina/boot | `DESKTOP-5T30P6J` / `2026-08-03T21:38:33.1818970Z` |
| Service identity | `NT SERVICE\SecureIntegrationBroker`; SID `S-1-5-80-375269102-3931153373-1436009693-879735287-3770408939` |
| Bundle locale | `C:\ProgramData\SecureIntegration\LiveMatrix\m0-m1-20260803-232955\evidence\M0-M1-live-matrix-m0-m1-20260803-232955.zip` |
| SHA-256 bundle | `5B6E9997EF0C5C482B27B7DB63323BA54C96D5C2B083DAAEB4A47255D156C52C` |
| Completamento UTC | `2026-08-03T21:40:05.9525444+00:00` |

Questa sezione è generata solo dopo una run elevata, un reboot osservato e tutti i fail-closed check superati. Il bundle non è simulato e non è versionato nel repository.
<!-- LIVE-MATRIX-AUTOMATION:END -->

## Coperture residue non bloccanti per il gate live

1. PID reuse deterministico e sostituzione immagine durante capture/authorize.
2. Authenticode positive path con eseguibile test firmato e chain policy controllata.
3. Aggregate payload 16 MiB, streaming 64 MiB e backpressure.
4. GitHub Actions su remote Windows runner e firma degli artefatti.

La decisione M2 resta NO-GO finché il commit testato non è integrato in `origin/main`. Se l'integrazione riscrive lo SHA, la matrice completa deve essere ripetuta.
