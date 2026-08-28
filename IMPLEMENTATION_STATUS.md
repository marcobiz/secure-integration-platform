# Implementation dashboard

Aggiornato: 2026-08-24
Baseline CURRENT: `origin/main` = `97daa565f582d575da5d61665126c50ea52be3ed`

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
| Productization `0.1.0-alpha.1` | **PUBLIC TECHNICAL PREVIEW governance candidate; non pubblicata** | REST/Direct/clean baseline chiuse e adopter simulation PASS. Licenza path-based, DCO/security/CoC e release metadata sono candidate implementate; review indipendente, integrazione e publication gate restano aperti. |
| Produzione enterprise | **Non qualificata** | Azure live, MSI, adapter native/COM, HA/DR, restore/load/soak, pentest, firma artefatti e pilot restano fuori dal CURRENT. |

## Due sole track attive

### Track A — Core `0.1.0-alpha.1`

TARGET: una developer alpha non-production, provider-neutral, con un solo percorso
supportato e ripetibile:

```text
Direct .NET
→ Gateway
→ Connector REST Published
→ Synthetic Provider
→ mock HTTPS/mTLS
→ risposta sanificata e audit metadata-only
```

FSE2, MSI, COM/C ABI, Azure live, HA/DR e stabilità API non sono promesse della release.
Scope e gate ALPHA-01..08 sono in
[`docs/implementation/0.1.0-alpha-scope.md`](docs/implementation/0.1.0-alpha-scope.md).

### Track B — FSE2 Organization OfficialTest

TARGET iniziale: `validate-cda` nell'ambiente ufficiale di test, con dataset sintetico
autorizzato e evidence redatta. Solo dopo si affrontano `attachment_hash` sugli exact
file bytes, create/replace, status e gli ulteriori workflow autorizzati. Questa track usa
un pack verticale opzionale e non amplia le dipendenze del Core.

Candidate non ancora integrato `FSE2-OFFICIALTEST-OPERATIONALIZATION`: source canonica per il solo
`validate-cda`, compilatore di piano protetto, composizione A1 mTLS/S1 dual-signing e provisioner
verticale sulle superfici Admin esistenti. Il candidate usa lookup provider esatti non paginati,
compone il path runtime preservando l'intero prefisso OfficialTest e vincola il publish server-side
alla sessione dell'exact `approved_by`. Il candidate non contiene configurazione reale e non
esegue rete OfficialTest. Stato gate dichiarabile: T01/T02/T03 PASS software/offline,
T04 `BLOCKED_PENDING_OPERATIONAL_CONFIGURATION_AND_LIVE_CALL`, T06 PARTIAL.

## Candidate ALPHA-GOV-REL

| Slice | Stato candidate | Limite |
|---|---|---|
| ALPHA-LIC | **Candidate implemented, pending independent review/integration** | MPL-2.0 default, override Apache-2.0 e dual license `OR` sono path-based e verificati; non è un publication GO. |
| ALPHA-SEC | **Candidate implemented, pending independent review/integration** | Security contact, Contributor Covenant 3.0 e DCO 1.1 sono configurati; il required-check DCO richiede handoff di branch protection dopo integrazione. |
| ALPHA-DOC-04 | **Candidate truth-aligned** | FSE2 resta synthetic-qualified con A1/S1, Local PKCS12 e vertical image opzionali; nessun materiale reale, OfficialTest o claim production. |
| ALPHA-REL | **NOT CLOSED** | Nessun tag, GitHub Release, registry/NuGet publication o merge è autorizzato da questa slice. |

`PUBLIC_RELEASE_GO = NO` e `PRODUCTION_READY = NO` fino a review indipendente, integrazione e publication gate sull'exact release commit.

## Exact-main precheck del technical candidate

L'exact main autorizzato per ALPHA-GOV-REL è `97daa565f582d575da5d61665126c50ea52be3ed`.
General CI è **6/6 PASS** e M5/Admin CI è **15/15 PASS** sulla baseline. Il candidate
non crea tag, release GitHub o pubblicazioni registry e mantiene
`PUBLIC_RELEASE_GO = NO` / `PRODUCTION_READY = NO`.

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

## Core export storico e candidate normalizzato

- inventario: **431 file**;
- allowlist/hash/byte entries: **431/431**;
- `packs/deployment` esclusi;
- `Healthcare` e `ConnectorPacks` esclusi;
- SHA-256 raw del manifest della run exact-main:
  `CC622E4F8FCACE420232C99B4F474429E22C2259DD1B2829B6C55BBD265D6234`.

Il raw SHA è evidence della singola run e non è un expected cross-run, perché il manifest
include `generatedAtUtc`. Il candidate `0.1.0-alpha.1` aggiunge
`normalizedInventorySha256`, distinto dal manifest run-specific e calcolato su exact
commit, file count, path ordinal normalizzati, byte count e SHA-256 per file.
`P3-CORE-EXPORT-DIGEST` è chiuso dalla slice candidate senza reinterpretare i raw SHA
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

1. Revisionare e integrare ALPHA-LIC, ALPHA-SEC e ALPHA-DOC-04 sull'exact candidate.
2. Attivare il gate DCO come required check con configurazione GitHub esterna dopo integrazione.
3. Mantenere DOC-04 e la track FSE2 separate dalla preview Core.
4. Creare il futuro tag `v0.1.0-alpha.1` o pubblicare soltanto con nuova autorizzazione
   dopo tutti i gate ALPHA-01..08.

Il backlog operativo e la stop list sono in
[`docs/implementation/backlog.md`](docs/implementation/backlog.md).

## Regole di aggiornamento

- aggiornare questa dashboard quando cambia lo stato integrato in `main` o un gate esterno
  viene attestato;
- conservare cronologie dettagliate, SHA candidati e remediation nei report dedicati;
- qualificare sempre l'evidenza come synthetic, live lab, official-test o production;
- non trasformare input del maintainer in evidence repository;
- non versionare certificati, chiavi, token, endpoint riservati, JWT o payload sanitari.
