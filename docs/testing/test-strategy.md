# Test strategy

Questa strategia distingue test automatizzati, gate environment-specific, qualifica
esterna e lavoro differito. La matrice canonica requisito → test → evidence/state è
[`requirements-traceability.md`](../traceability/requirements-traceability.md); un
conteggio aggregato non costituisce da solo evidence.

## Principi

- negative path e comportamento fail-closed sono test di prima classe;
- synthetic test, live lab controllato, OfficialTest e production sono livelli distinti;
- nessuna fixture contiene secret riusabili, certificati reali, dati sanitari o risposte
  esterne raw;
- uno skip in un gate richiesto non è un PASS;
- una failure resta visibile e il gate viene rieseguito solo sull'exact commit corretto;
- ogni claim è legato a test nominativi e alle precondizioni dell'ambiente.

## Stati di evidence

| Stato | Significato |
|---|---|
| `AUTOMATED` | Test nominativo eseguito da una suite ripetibile; il PASS vale per l'exact commit/run. |
| `EXTERNAL` | Richiede un servizio o ambiente amministrato esterno e un'attestazione separata. |
| `MANUAL` | Procedura operatore documentata, non sostituita da un test automatico. |
| `DEFERRED` | Lavoro pianificato non necessario per il claim corrente. |
| `BLOCKED` | Precondizione o difetto noto impedisce il claim. |
| `UNVERIFIED` | Codice/design presente ma nessuna evidence sufficiente registrata. |

Un requisito può avere più righe/stati: ad esempio comportamento Core `AUTOMATED` e
deployment cloud `EXTERNAL/UNVERIFIED`.

## Copertura automatizzata corrente

| Livello | Superfici principali |
|---|---|
| Unit | DPAPI/AES-GCM, redaction, authorization/grant, canonicalizzazione/checksum, Connector schema/validator, lifecycle, endpoint/header/path policy, SSRF, replay, OAuth/SOAP/session/JWT/signing foundation e XML hardening. |
| Integration | IPC e identity Windows, enrollment/renewal/revocation/BGW1, PostgreSQL 18 migration/RLS/privilegi, publish/four-eyes/binding/cache/rollback, restricted egress/TLS/mTLS e provider sintetici. |
| Architecture | Dipendenze Core/pack, assenza di capability vietate, export Core, provider boundary e contratti runtime. Alcune guardie sono source-text checks e non sostituiscono audit assembly/IL. |
| Hosted/E2E sintetico | Broker/Direct verso lo stesso runtime, Connector REST, Admin import-to-invoke, SOAP/session/capability bridge e pack verticali contro server/certificati sintetici. |
| Admin Web | lint, TypeScript strict, generated contract checks, Vitest, Playwright mock UI, accessibility e full-stack con Gateway/PostgreSQL/provider/vendor mock. |
| Supply chain | secret scan, dependency/npm audit nei job pertinenti, container checks, base-image validation, Core export e SBOM SPDX. |

Le primitive OAuth Authorization Code/PKCE e Client Credentials hanno test di
foundation, ma il Gateway host corrente non registra una execution strategy OAuth E2E.
Non sono quindi un Connector OAuth esterno qualificato.

## Gate con ambiente dedicato

| Gate | Ambiente e claim consentito |
|---|---|
| Windows Broker | Windows host con Service/virtual account, Named Pipe, ACL, DPAPI e process identity reali; non prova MSI o adapter native. |
| PostgreSQL 18 | Istanza/container dedicato, identity migration/runtime/admin separate, fresh/upgrade/no-op, FORCE RLS e race; il test deve eseguire, non risultare skipped. |
| Container/M3A | Docker Linux, non-root/read-only/tmpfs dove configurati, network split e mock TLS; qualifica il laboratorio sintetico, non un cloud production deployment. |
| Admin full-stack | Gateway/Admin, PostgreSQL 18, Synthetic Provider e vendor mock senza intercettare Admin API/auth; prove di rollback restano test nominativi separati. |
| Local PKCS#12 lab | Pack opt-in, materiale sintetico per-run esterno a Git, non-root/read-only e tamper/readiness; nessun import ufficiale o live external call. |
| M3B Azure | Workflow separato e autorizzato; non qualificato live sulla baseline corrente. |
| FSE2 OfficialTest | Ambiente ufficiale, provider/custody/import e driver separati; nessun outcome corrente. `validate-cda` è il primo futuro. |

## UI trust boundary

- `npm run test:ui-mock` intercetta chiamate con `page.route`: è browser/component, non
  product E2E.
- `tools/m5/Invoke-M5FullStack.ps1` usa API e processi reali del laboratorio full-stack;
  DevelopmentAuth è limitata al peer loopback.
- l'integrazione OIDC sintetica usa il vero handler ASP.NET Core e verifica code, PKCE,
  state, nonce, issuer/subject, cookie, session rotation, logout e negativi; non qualifica
  un identity provider esterno.
- i test UI coprono ruoli, CSRF/RBAC/tenant scope, four-eyes, EN/IT, keyboard e axe senza
  finding critical/serious.

## Security test policy

Ogni modifica security-sensitive aggiunge almeno un caso positivo e uno negativo sulle
authority pertinenti: identity, grant, Published revision, binding/provider resource,
replay, endpoint/DNS, credential, signing scope, race A→B, redaction e cleanup.

Sono automatizzati bounds e malformed input deterministici per JSON/XML/IPC, traversal e
ambiguous encoding, SSRF IPv4/IPv6/DNS rebinding, header injection/hop-by-hop,
XXE/entity expansion, replay/PID reuse, provider failure e secret canary. Non vengono
descritti come fuzzing finché non esiste un harness fuzz dedicato con corpus, durata e
crash triage.

## PostgreSQL e audit

I test PostgreSQL nominativi provano migration checksum/fresh/no-op, ruoli, FORCE RLS,
tenant isolation, publication/binding/locator e transazioni/race. I test metadata-only
provano che payload e credential non entrano negli eventi.

La baseline non ha un test che neghi UPDATE audit al ruolo `gateway_admin`, perché la
grant storica lo consente. Quel controllo è `DEFERRED`, non può essere inferito dai test
runtime INSERT-only o da un conteggio complessivo PASS.

## SBOM ed export

`eng/generate-sbom.ps1` produce SPDX per gli artefatti applicativi e un aggregate manifest
con SHA-256/exact commit. Il job Linux aggiunge il documento container tramite Syft;
`eng/validate-sbom.ps1` e `eng/test-sbom-modes.ps1` verificano completezza e fail-closed.
CycloneDX, artifact signing e provenance pubblicata non sono implementati.

Il SHA del manifest raw del Core export include metadata run-specific e non è usato come
digest deterministico cross-run. La normalizzazione resta `DEFERRED` sotto
`ALPHA-ART`/`P3-CORE-EXPORT-DIGEST`.

## Gap pianificati

| Area | Stato e gate richiesto |
|---|---|
| Fuzzing | `DEFERRED`: harness stateful, corpus versionato, budget e crash regression. |
| Performance/load | `UNVERIFIED`: baseline ripetibile throughput/latency/provider cache/PostgreSQL. |
| IPC large payload | `DEFERRED`: implementare `Data`/`End` e backpressure o ridurre i limiti dichiarati. |
| Coverage/SAST | `UNVERIFIED`: soglia coverage e CodeQL/SAST dedicato non sono gate correnti. |
| Module provenance | `DEFERRED`: manifest/hash/CMS/publisher/tamper; il loader controlla path/identity/MVID, non firma. |
| Installer/legacy | `DEFERRED`: MSI, C ABI/COM, x86/x64 e compatibility matrix. |
| Resilienza enterprise | `UNVERIFIED`: load/soak, backup/restore, failover, HA/DR, recovery e pentest. |
| Servizi esterni | `EXTERNAL`: Azure live, OIDC reale e FSE2 OfficialTest non sono dedotti dai mock. |

## Fixture ed evidence

- usare domini riservati, identità sintetiche e certificati generati per-test;
- non salvare response reali, token, PFX/PEM/P12, activation code o dati clinici;
- eseguire canary/secret scan anche su log, browser output e package staging;
- conservare evidence raw fuori repository in una directory protetta;
- nel repository restano manifest redatti, test ID, exact commit e hash;
- prima di dichiarare un gate esterno PASS, registrare ambiente, precondizioni, outcome e
  limite della qualifica senza pubblicare materiale riservato.
