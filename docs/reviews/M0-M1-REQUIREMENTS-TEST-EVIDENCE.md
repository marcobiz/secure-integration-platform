# Matrice M0/M1: requisito → test → evidenza

Data review: 2026-08-03. Baseline esaminata: commit `7f68442ceb9adcc47bb1b1a534ad64e23bd26bac`, tag `baseline-m0-m1-vslice-2026-08-03`.

## Legenda

- **PASS-A**: test automatico eseguito in questa review.
- **PASS-C**: evidenza ottenuta da checkout pulito del tag baseline.
- **PASS-S**: verifica statica o gate di repository; non sostituisce una prova live.
- **PARZIALE**: una parte è automatizzata, ma manca l'evidenza richiesta.
- **OPEN-LIVE**: richiede Windows Service/identità distinte su macchina pulita o VM e non è stato eseguito.
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
| FR-003 — autorizzazione Application/operation | `IT_BRK_Authorized_application_uses_pipe_and_unauthorized_hash_is_denied`; `Named_pipe_ACL_is_protected_and_contains_only_configured_principals`; `HMAC_requires_an_explicit_secret_operation_grant`; grant negativo nel test E2E | PASS-A/PARZIALE | Processo realmente distinto sotto stesso utente e altro utente: OPEN-LIVE. Publisher Authenticode ha solo negative path su binario unsigned. |
| FR-004 — Put/Delete senza GetSecret | `UT_BRK_LocalSecretLifecycle`; `Local_secret_delete_is_idempotent_and_cross_application_use_is_denied`; `Local_storage_rejects_non_local_secret_classes`; `Public_API_has_no_GetSecret_operation` | PASS-A | Lifecycle attraverso servizio installato e restart reale: OPEN-LIVE. |
| FR-005 — AEAD/key versioning | `UT_CRYPTO_AeadRoundTripTamperRotation`; `AES_GCM_nonce_is_unique_across_repeated_protection`; `AEAD_authenticates_application_purpose_and_content_type`; `AEAD_rejects_unknown_key_version_without_trying_another_key`; `AEAD_rejects_malformed_envelope`; `AC005_Installation_key_and_ciphertext_differentiation` | PASS-A | Rotazione operativa/atomica non implementata. |
| FR-006 — HMAC M1 | `UT_BRK_LocalSecretLifecycle`; `HMAC_requires_an_explicit_secret_operation_grant`; `Repository_reopen_recovers_keys_secrets_and_protected_data_under_same_identity` | PASS-A | Firma e certificato locale: OUT (M7). |
| FR-015 — SDK .NET, porzione M1 | SDK usato da `IT_BRK_*`, concurrency e vertical slice E2E; build `netstandard2.0`/`net10.0` | PASS-A | .NET Framework/COM/C ABI/CLI: OUT (M6); IPC non congelato. |
| FR-018 — operazioni locali offline | `DPAPI_CurrentUser_round_trip_and_ciphertext_is_not_plaintext`; `Offline_storage_contains_no_plaintext_and_corruption_is_denied`; `Repository_reopen_recovers_keys_secrets_and_protected_data_under_same_identity` | PASS-A/PARZIALE | DPAPI sotto virtual service account e restart servizio reale: OPEN-LIVE. |

## M1 — requisiti non funzionali e superfici mirate

| Requisito/superficie | Test/evidenza eseguita | Stato | Gap esplicito |
|---|---|---|---|
| NFR-001 — secret/log redaction | `Wire_errors_redact_invalid_payload_and_cryptographic_failure`; `Audit_logging_redacts_normal_and_authentication_denied_paths`; E2E secret-boundary; secret scan | PASS-A/PARZIALE | Windows Event Log del servizio reale e corpus telemetry completo: OPEN-LIVE/debito. |
| NFR-002 — deny-by-default | unauthorized hash/publisher, cross-application secret, secret operation grant, Gateway grant negativo | PASS-A | SID differente a livello OS: OPEN-LIVE. |
| NFR-004 — limiti IPC | `IPC_frame_accepts_exact_hard_limit`; `IPC_frame_rejects_body_above_hard_limit`; malformed/truncated/header tests | PARZIALE | Aggregate 16 MiB e stream 64 MiB non assemblati dall'SDK/server. |
| NFR-005 — timeout/cancel/idempotenza | `Pipe_supports_concurrent_clients_and_deadline_cancellation`; `Same_connection_multiplexes_requests_and_honors_cancel_frame`; delete idempotente; stress 20× sui critical IPC tests | PASS-A per M1 | Retry/circuit breaker appartengono a M2+. |
| NFR-006 — correlation | E2E verifica `X-Correlation-Id` Broker→Gateway | PARZIALE | W3C trace context completo non implementato. |
| NFR-008 — build/SBOM | clean checkout, build warning-free, vulnerability scan, SPDX | PASS-A/PASS-C | Firma artefatti non prevista in M0/M1. |
| NFR-010 — no persistence centrale payload | E2E harness mantiene payload solo in memoria; ispezione storage locale | PASS-A nel vertical slice | Nessun Gateway production/DB presente. |
| Framing/version/handshake | `IPC_frame_round_trip_preserves_network_header_and_payload`; hard-limit/malformed/EOF/unknown JSON tests; `Handshake_rejects_nonzero_sequence_and_malformed_nonce` | PASS-A | Fuzzing stateful non eseguito. |
| Multiplexing/cancellation | `Same_connection_multiplexes_requests_and_honors_cancel_frame`; `Pipe_supports_concurrent_clients_and_deadline_cancellation`; stress 20/20 | PASS-A | SDK persistente condiviso non implementato. |
| PID reuse/creation time/handle | `Named_pipe_caller_identity_is_captured_from_the_kernel` verifica PID, path, creation time e chiusura handle processo/file | PARZIALE | PID reuse forzato non è automatizzato; richiede harness/VM dedicato. |
| Race identity→authorization | Code review: process handle e handle read-only dell'eseguibile restano aperti per la connessione; start time ricontrollata; snapshot hash/publisher usato dall'authorizer | PASS-S + test handle | Nessun fault-injection test che sostituisca l'immagine tra capture e authorize. |
| ACL storage | `Broker_storage_ACL_is_protected_and_has_no_world_grant` | PASS-A/PARZIALE | Enforcement con service SID vs utenti distinti: OPEN-LIVE. |
| ACL pipe | `Named_pipe_ACL_is_protected_and_contains_only_configured_principals` | PASS-A/PARZIALE | Access-denied reale per SID differente: OPEN-LIVE. |
| DPAPI CurrentUser | DPAPI round-trip/ciphertext e differenziazione Installation | PARZIALE | Root DPAPI della virtual service identity non dimostrata: OPEN-LIVE. |
| Nonce AES-GCM | 512 envelope con stessa key/plaintext, nonce 96-bit tutti distinti | PASS-A | Test statistico, non prova matematica del CSPRNG; usa `RandomNumberGenerator`. |
| Metadata AAD | test Application, Installation, purpose e content type errati | PASS-A | Nessun metadata client non previsto è accettato dal JSON. |
| Key versioning/corruzione | rotation/tamper, unknown version, key DPAPI corrotta, secret JSON/base64 corrotto | PASS-A | Scrittura atomica di `active.txt` e comando rotation restano debito. |
| Redazione errori | wire response controllata per invalid base64 e auth tag; audit controllato per normal/denied/error | PASS-A/PARZIALE | EventLog live e crash/unhandled exception path: OPEN-LIVE. |

## Acceptance criteria M0/M1

| AC | Stato gate | Evidenza/nota |
|---|---|---|
| AC-001 | PASS-A per vertical slice | Vendor API key solo nel Gateway harness; assente dal client/Broker/audit. |
| AC-002 | **OPEN-LIVE — blocker** | Script/DI dichiarano virtual account, ma nessun servizio installato è stato osservato. |
| AC-003 | PARZIALE | Policy/hash/publisher/grant automatici passano; processo e utente realmente distinti restano live. |
| AC-004 | **OPEN-LIVE — blocker** | ACL e DPAPI sono testate sotto l'identità del testhost, non service identity vs gestionale. |
| AC-005 | PASS-A | Due repository/Installation producono key e ciphertext differenti. |
| AC-006 | PARZIALE | Wire/audit automatici passano; EventLog del servizio reale manca. |
| AC-007 | PASS-A nel harness | Nessun secret nelle response del Gateway harness. |
| AC-008 | PASS-S/PASS-A | Broker dipende solo da `IGatewayInvoker`; nessun provider Vault. |
| AC-009 | PASS-A nel perimetro | Request senza URL, base address HTTPS fissata, TLS negativo. |
| AC-010 | PASS-A nel perimetro | Nessuna secret reference Gateway; grant Connector/operation fisso. |
| AC-020 | PASS-C | Checkout pulito del tag compila e testa con SDK richiesto installato. |
| AC-021 | PASS-A | Vertical slice sintetico ripetibile. |
| AC-023 | PASS-A | Secure Layer E2E. |
| AC-027 | PASS-A | SPDX generato. |

Gli AC non elencati dipendono da M2 o milestone successive e non vengono anticipati.

## Requisiti non ancora automatizzati

1. Installazione/avvio/arresto/riavvio come Windows Service su virtual account reale.
2. Enforcement pipe/storage e fallimento DPAPI tra tre identità Windows distinte.
3. Persistence dopo restart del vero servizio, inclusa ricostruzione del profilo account.
4. Windows Event Log redaction con i quattro failure path richiesti.
5. PID reuse deterministico e sostituzione immagine durante capture/authorize.
6. Authenticode positive path con eseguibile test firmato e chain policy controllata.
7. Aggregate payload 16 MiB, streaming 64 MiB e backpressure.
8. GitHub Actions su remote Windows runner e firma degli artefatti.
