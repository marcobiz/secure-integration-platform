# Implementation dashboard

Aggiornato: 2026-08-24
Baseline CURRENT: `origin/main` = `ee3072be5e34a7b0477907a2580dcf454b8a4aba`

Questo file descrive lo stato integrato corrente. I dettagli storici restano nei tag,
nei report di test e nelle review già versionate; non vengono ricopiati qui. I termini
**CURRENT**, **TARGET** e **HISTORICAL** distinguono rispettivamente ciò che è integrato,
ciò che è ancora da ottenere e l'evidenza immutabile di baseline precedenti.

## Quadro CURRENT

| Area | Stato corrente | Evidenza o limite |
|---|---|---|
| M0-M2 — fondamenta, Local Broker e Gateway | **Done** | Baseline e gate live storici restano attestati dai tag; non equivalgono a un installer release. |
| M3A — vertical slice production-like | **PASS live lab** | Tag `m3a-product-gate-pass-20260805`; M3B Azure resta non qualificato live. |
| M4 — Connector Configuration | **Done** | Lifecycle, Published runtime, PostgreSQL 18, CLI e quickstart sintetico integrati. |
| M5 — Admin UI/API | **Done** | OIDC/RBAC/four-eyes, Admin API/UI e confini provider integrati. |
| M5.5 — Direct Gateway Access | **Done** | Sample .NET presente; il key storage process-local resta un limite non-production. |
| Authentication foundation / Wave 1 | **Integrata** | SOAP/session, JWT/X.509, signing slot, mTLS e moduli esterni hanno gate dedicati; nessuna primitive qualifica automaticamente un servizio esterno. |
| Healthcare — FSE2 Organization | **Synthetic-qualified** | Profilo Organization e 11 operation implementati con dual JWT S1 `contentCommitment` e A1 mTLS distinta; nessuna chiamata FSE2 live. |
| FSE2 Local PKCS12 e vertical image | **Integrati; synthetic lab qualified** | Provider opzionale, importer offline, overlay Compose e immagine verticale con `Healthcare.FSE2` integrati da PR #33. Il pack dichiara `SecretValues=false`; import/custody reali e OfficialTest restano aperti. |
| Healthcare — ePrescription regionale | **Foundation soltanto** | Profili regionali `BLOCKED_BY_SPEC`; non pubblicabili. |
| Productization `0.1.0-alpha.1` | **GitHub public prerelease pubblicata** | [Public Technical Preview](https://github.com/marcobiz/secure-integration-platform/releases/tag/v0.1.0-alpha.1) pubblicata dal source commit `ee3072be5e34a7b0477907a2580dcf454b8a4aba`; non equivale a production readiness o qualifica FSE2 OfficialTest. |
| Produzione enterprise | **Non qualificata** | Azure live, MSI, adapter native/COM, HA/DR, restore/load/soak, pentest, firma artefatti e pilot restano fuori dal CURRENT. |

## Release Core pubblicata e track corrente

### Core `0.1.0-alpha.1` — esito pubblicato

La release pubblicata è una developer alpha non-production, provider-neutral, con un
solo percorso supportato e ripetibile:

```text
Direct .NET
→ Gateway
→ Connector REST Published
→ Synthetic Provider
→ mock HTTPS/mTLS
→ risposta sanificata e audit metadata-only
```

FSE2, MSI, COM/C ABI, Azure live, HA/DR e stabilità API non sono promesse della release.
Il resoconto e l'inventario pubblico verificato sono nelle
[release notes](docs/releases/0.1.0-alpha.1.md) e nella
[publication attestation](docs/releases/0.1.0-alpha.1-publication-attestation.json).

### Track corrente — FSE2 Organization OfficialTest

TARGET iniziale: `validate-cda` nell'ambiente ufficiale di test, con dataset sintetico
autorizzato e evidence redatta. Solo dopo si affrontano `attachment_hash` sugli exact
file bytes, create/replace, status e gli ulteriori workflow autorizzati. Questa track usa
un pack verticale opzionale e non amplia le dipendenze del Core.

## Esito ALPHA-GOV-REL

| Slice | Stato | Limite |
|---|---|---|
| ALPHA-LIC | **PASS** | MPL-2.0 default, override Apache-2.0 e dual license `OR` sono path-based e verificati; non costituisce un claim production. |
| ALPHA-SEC | **PASS** | Security contact, Contributor Covenant 3.0 e DCO 1.1 sono configurati. |
| ALPHA-DOC-04 | **PASS — truth-only** | FSE2 resta synthetic-qualified con A1/S1, Local PKCS12 e vertical image opzionali; nessun materiale reale, OfficialTest o claim production. |
| ALPHA-REL | **PASS** | Tag annotato e GitHub public prerelease pubblicati sull'exact source commit; nessuna pubblicazione NuGet/registry e nessuna qualifica production/FSE2. |

`PUBLICATION_OCCURRED = YES` e `PRODUCTION_READY = NO`. La pubblicazione è un evento
distinto dalla readiness e da qualunque qualifica di servizio esterno.

## Exact source della prerelease pubblicata

Il tag annotato `v0.1.0-alpha.1` e la GitHub Release puntano a
`ee3072be5e34a7b0477907a2580dcf454b8a4aba`. La release pubblica è una prerelease con
classificazione **PUBLIC TECHNICAL PREVIEW**. I nove asset, i loro byte count e i digest
GitHub sono fissati dalla publication attestation; i cinque artefatti prodotto sono
coerenti con manifest, `SHA256SUMS` e digest GitHub. Il valore storico
`claims.publicReleaseGo=false` nel manifest pubblicato è classificato come errata di
stato pre-pubblicazione senza impatto sull'integrità.

## PR #33 — evidence storica preservata

PR #33 è stata integrata tramite fast-forward; il suo head storico coincideva con
`eec2fa5556eccc7e8e3b47fc7d7b127bcac1ed9e`.

| Controllo exact-main | Esito |
|---|---|
| General CI | **6/6 PASS**, run [`31677839993`](https://github.com/marcobiz/secure-integration-platform/actions/runs/31677839993) |
| M5/Admin CI | **15/15 PASS**, run [`31677840011`](https://github.com/marcobiz/secure-integration-platform/actions/runs/31677840011) |
| PostgreSQL 18 FSE2 canonico | **1/1 PASS**, zero skip |
| Local PKCS12 provider | **30/30 PASS**, materiale esclusivamente sintetico |
| Architecture | **42/42 PASS** |
| Provider-active synthetic lab | **PASS** |
| Security micro-review | **GO** sul perimetro sintetico di PR #33 |

L'integrazione comprende provider Local PKCS12 opzionale, importer sintetico/offline,
immagine verticale contenente `Healthcare.FSE2`, overlay Compose, provider-active lab,
firma S1 `contentCommitment` e identità mTLS A1 distinta. L'immagine Gateway Core
predefinita continua a non includere il pack verticale.

Questi esiti **non** attestano accesso o import del materiale reale, custody reale,
configurazione OfficialTest, chiamate FSE2, `validate-cda` live, accreditamento software,
create/status live o qualifica production. Nessun materiale reale è stato consultato o
importato durante PR #33 e nessuna chiamata live è stata eseguita.

## Core export storico e release normalizzata

- inventario: **431 file**;
- allowlist/hash/byte entries: **431/431**;
- `packs/deployment` esclusi;
- `Healthcare` e `ConnectorPacks` esclusi;
- SHA-256 raw del manifest della run exact-main:
  `CC622E4F8FCACE420232C99B4F474429E22C2259DD1B2829B6C55BBD265D6234`.

Il raw SHA è evidence della singola run e non è un expected cross-run, perché il manifest
include `generatedAtUtc`. La release `0.1.0-alpha.1` aggiunge
`normalizedInventorySha256`, distinto dal manifest run-specific e calcolato su exact
commit, file count, path ordinal normalizzati, byte count e SHA-256 per file.
`P3-CORE-EXPORT-DIGEST` è chiuso dalla release senza reinterpretare i raw SHA
storici.

## Tassonomia delle evidenze

| Classe | CURRENT | Non implica |
|---|---|---|
| Synthetic | Core, profilo FSE2, provider Local PKCS12, importer e vertical image hanno gate sintetici. | Accesso a un servizio esterno o custody reale. |
| Live lab | Local Broker/M3A hanno evidenza live di laboratorio sulle baseline attestate. | Production o OfficialTest FSE2. |
| Official-test | Nessuna configurazione o chiamata FSE2 OfficialTest è attestata. | `validate-cda`, create/status o accreditamento. |
| Production | Nessuna qualifica production è corrente. | Readiness enterprise, HA/DR o provider production-grade. |

La matrice requisito-test-evidenza canonica resta
[`docs/traceability/requirements-traceability.md`](docs/traceability/requirements-traceability.md).
I conteggi aggregati sopra sono checkpoint di PR #33, non sostituti dei test nominativi o
dei gate di release.

## Priorità operative

1. Mantenere la track FSE2 OfficialTest separata dalla prerelease Core e non chiuderne i gate senza evidence live autorizzata.
2. Risolvere i tre follow-up di contratto documentale registrati nel backlog senza ampliarli in questa PR.
3. Per la prossima release, applicare il contratto candidato/pubblicazione e chiudere pubblicamente l'integrità di manifest, checksum e asset ausiliari.

Il backlog operativo e la stop list sono in
[`docs/implementation/backlog.md`](docs/implementation/backlog.md).

## Regole di aggiornamento

- aggiornare questa dashboard quando cambia lo stato integrato in `main` o un gate esterno
  viene attestato;
- conservare cronologie dettagliate, SHA candidati e remediation nei report dedicati;
- qualificare sempre l'evidenza come synthetic, live lab, official-test o production;
- non trasformare input del maintainer in evidence repository;
- non versionare certificati, chiavi, token, endpoint riservati, JWT o payload sanitari.
