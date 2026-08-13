# Deployment e packaging

Questo documento separa gli artefatti **CURRENT** dai target di release e produzione.
La presenza di un ADR, Dockerfile o skeleton IaC non equivale a packaging pubblicato,
qualifica cloud o readiness production.

## CURRENT — Local Broker

Sono presenti il Windows Service .NET, la configurazione, lo SDK .NET in sorgente e gli
script PowerShell `deploy/windows/install-service.ps1` e `uninstall-service.ps1`.

Non sono presenti come artefatti distribuibili e qualificati:

- MSI/WiX con install/repair/upgrade/rollback/uninstall matrix;
- DLL C ABI, COM/type library o pacchetti x86/x64;
- NuGet/CLI pubblicati e firmati;
- updater, recovery o rollback package.

Gli script Windows sono strumenti di sviluppo/laboratorio e non chiudono AC-019.

## CURRENT — container Core

Il repository contiene immagini distinte per `Gateway.Api` e `Gateway.Migrations`. Il
Gateway non esegue auto-migrate all'avvio. L'immagine Gateway usa una base ASP.NET Debian
pinned per tag patch e manifest-list digest e gira come utente non-root. Non è chiseled e
la base contiene una shell. Read-only filesystem e `tmpfs` sono imposti dai profili
Compose/CI che li configurano, non dal Dockerfile isolato.

`/health/live` verifica il processo. `/health/ready` verifica registry e provider health;
non prova HA, backup, restore o conformance di un servizio esterno.

### Base image .NET

`global.json` seleziona SDK `10.0.302` con `rollForward: latestPatch`. Ogni
`FROM mcr.microsoft.com/dotnet/...` usa un tag patch leggibile e il digest della manifest
list. I tag mobili, `ARG`/interpolazione e `FROM --platform` .NET sono negati.

`eng/validate-container-base-images.ps1` è il controllo fail-closed. Sulla baseline
corrente l'inventario repository è di sette Dockerfile Git-tracked e quattordici
occorrenze `FROM` .NET:

- `src/Gateway/Gateway.Api/Dockerfile`;
- `src/Gateway/Gateway.Migrations/Dockerfile`;
- `packs/deployment/azure/Dockerfile`;
- `packs/deployment/local-pkcs12/Dockerfile`;
- `tools/m3/VendorMock/Dockerfile`;
- `tools/m3/SyntheticVault/Dockerfile`;
- `tools/m3/Provisioner/Dockerfile`.

Il validator controlla inventario ordinale, parser, tag/digest, mapping e allineamento
SDK. Un nuovo Dockerfile o una rotazione dei pin richiede modifica intenzionale del
controllo, build con pull/no-cache, non-root/read-only gate, secret/vulnerability scan,
SBOM e qualifica exact-head. Un profilo export senza metadata Git ha un inventario Core
separato e non riduce il controllo del repository.

## CURRENT — quickstart locale senza cloud

I quickstart M4/M5 compongono:

- PostgreSQL 18 e provisioner/migration runner;
- Gateway non-root con Admin UI statica;
- Synthetic Provider;
- mock vendor HTTPS/mTLS;
- fixture, CA e credenziali sintetiche per-run sotto `.artifacts` ignorata.

M4 usa la CLI per elencare e testare un Connector Published. M5 aggiunge
DevelopmentAuth locale, enrollment reale challenge/PoP, ruoli distinti, four-eyes,
binding/grant, runtime mTLS/BGW1, audit e post-retire denial. Solo la porta HTTPS Gateway
è pubblicata su loopback; PostgreSQL, provider e mock restano nella rete Compose privata.

Questi gate sono ambienti di build/test/evaluation. Non sono deployment cloud,
OfficialTest o production. Il PostgreSQL del Compose usa SSL disabilitato all'interno
della rete privata: non è evidenza di TLS database production.

Runbook:

- [M4 local quickstart](../operations/M4-QUICKSTART.md);
- [M5 Admin quickstart](../operations/M5-ADMIN-QUICKSTART.md).

## CURRENT, opt-in — pack local PKCS#12

`packs/deployment/local-pkcs12` è un pack esterno alla solution/export Core. Dipende solo
dalle astrazioni provider-neutral, dichiara `SecretValues=false` e fornisce un generic
secret provider deny-only. Il Gateway non richiede secret retrieval quando la Published
operation usa le capability certificate/signing dichiarate.

L'overlay `deploy/fse2/docker-compose.fse2-local.yml` è opt-in e ricrea soltanto il
Gateway dopo il quickstart sintetico canonico. Manifest e materiale sono montati
read-only da path esterni a Git; il container resta non-root/read-only.

La qualifica repository usa esclusivamente fixture PKCS#12/CSR/certificati sintetiche
per-run e prova validation, firma/certificato, readiness e tamper handling. Non importa
materiale ufficiale, non stabilisce custody HSM/KMS, non pubblica un profilo e non esegue
chiamate FSE2 live. Certificati ricevuti/correlati e import operativo restano eventi
distinti.

## CURRENT — pack Azure e Bicep

`packs/deployment/azure` è opzionale ed escluso dal Core. Il pack dipende dalle stesse
capability provider-neutral; il Core non contiene SDK o tipi Azure.

`deploy/azure-bicep/main.bicep` è uno skeleton/contratto; `m3-dev.bicep` è un template
smoke non-HA per il laboratorio M3B. M3B non ha una qualifica live attestata sulla
baseline. La presenza del pack, del Dockerfile e del Bicep non dimostra App Service,
Key Vault, Managed Identity, rete privata, PostgreSQL Flexible Server, observability o
backup/restore operativi.

## CURRENT — loader di moduli

Il loader richiede configurazione deployment con path DLL assoluto su drive locale,
assembly full name, module type e module ID. Nega UNC/device/mapped path, traversal,
reparse e duplicati; legge byte bounded una volta, controlla identity/MVID e carica lo
stesso buffer.

Non verifica ancora manifest/hash atteso, CMS o publisher allowlist. ACL e provenance
dei byte sono responsabilità del deployment. Un modulo caricato è full-trust in-process.
Il Gateway Core predefinito non include moduli healthcare; una vertical image downstream
non può invertire la dipendenza verso il Core.

## CURRENT — SBOM ed export

`eng/generate-sbom.ps1` produce documenti SPDX e un aggregate manifest con SHA-256 ed
exact commit. Il manifest grezzo include attributi run-specific: il suo SHA non è un
digest deterministico cross-run. `P3-CORE-EXPORT-DIGEST` resta lavoro futuro di
normalizzazione sotto `ALPHA-ART`.

L'export Core usa allowlist e gate boundary/license/secret/build/test. Non pubblica un
repository o una release. Non esiste ancora pipeline di `dotnet pack`/NuGet push,
container push, Authenticode, CMS, Cosign o release SemVer.

## TARGET — Core `0.1.0-alpha`

Artefatti e gate sono definiti in
[`0.1.0-alpha-scope.md`](../implementation/0.1.0-alpha-scope.md). Il target è una developer
alpha non-production con un solo golden path REST sintetico, checksum/SPDX/vulnerability
inventory, source archive, clean-clone e istruzioni riproducibili.

Licenza, security channel, versioning/tag, packaging e `ALPHA-ADOPT` restano gate aperti.
Non dichiarare early-adopter completion finché `ALPHA-ADOPT` non è chiuso. MSI/native/COM
non sono parte del golden path supportato.

## TARGET — FSE2 OfficialTest

La track verticale richiede image/composizione FSE2, Published OfficialTest binding,
provider/custody, import operativo, driver sicuro ed evidence redatta. Il primo outcome
futuro è `validate-cda`. Una prova sintetica o il laboratorio local PKCS#12 non chiudono
questi gate; OfficialTest non equivale a production.

## TARGET — production/enterprise

Prima di claim production servono almeno:

- installer/pacchetti firmati e compatibility matrix;
- artifact signature/provenance e registry/release controls;
- IaC qualificata per rete, provider, PostgreSQL, observability e isolation;
- migration rollout, canary/rollback, backup/PITR e restore test;
- RPO/RTO, load/soak, pentest, incident response, rotation e monitoring;
- hardening DB audit append-only e least privilege dimostrato.

Questi controlli richiedono un target reale e gate exact-head/ambiente. Non sono dedotti
dai laboratori sintetici o dagli ADR.
