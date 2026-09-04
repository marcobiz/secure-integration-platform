# Pilot locale

**Pubblico:** adottante che vuole provare il Core.
**Stato:** CURRENT, private preview sintetica.
**Risultato:** prima chiamata locale riuscita, risposta sanificata, audit metadata-only e
cleanup ownership-checked.

Questo è il pilot locale canonico del Core. Non richiede cloud, materiale FSE2, SQL,
`.env`, .NET SDK, Node, npm, curl, PostgreSQL sull'host o modifica del trust store.
Questi prerequisiti non si estendono al
[pilot FSE2 opzionale](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md#prerequisiti).

## Prerequisiti

- Git per ottenere la repository;
- Docker Engine/Desktop con Linux containers e Docker Compose;
- PowerShell 7 o Windows PowerShell 5.1;
- rete soltanto se immagini pinned o package usati dai build Docker non sono già in
  cache.

Eseguire i comandi dalla root della repository. Non installare un SDK per completare
questo pilot.

## Esecuzione

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Validate
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Run
```

`Validate` controlla Docker Linux/Compose e compila il sample nell'immagine SDK .NET
10.0.302 pinned. `Run` costruisce e avvia PostgreSQL 18, migrazioni, Gateway/Admin UI,
Synthetic Provider e mock HTTPS/mTLS. I tool .NET e Node sono eseguiti nei build o in
container non-root; il repository è montato read-only e il Docker socket non è montato.
La run crea una Installation Direct e un grant sintetici nell'ambiente isolato, quindi invoca
`sample-secure-service/submit` una sola volta.

Il successo termina con questi marker:

```text
ALPHA_GOLDEN_PATH_DIRECT_PASS
ALPHA_GOLDEN_PATH_OUTBOUND_PASS; POSITIVE_OUTBOUND_COUNT=1
ALPHA_GOLDEN_PATH_RESPONSE_PASS; SANITIZED=YES; AUDIT=METADATA_ONLY; LOGS=REDACTED
ALPHA_GOLDEN_PATH_CLEANUP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; SYNTHETIC_MATERIAL=0
ALPHA_GOLDEN_PATH_PASS
```

La risposta applicativa decodificata contiene `accepted: true` e il riferimento
`synthetic-order`. Significano soltanto che il mock locale ha accettato la richiesta;
non sono un risultato business o una qualifica di servizio esterno.

## Interruzione e recovery

Se il processo viene interrotto, eseguire:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop
```

`Stop` rimuove solo risorse e materiale contrassegnati come proprietà del runner. Dopo
il cleanup, ripetere `Validate` e `Run`; non modificare container, volume o database a
mano. La run non supporta resume intermedio.

Un maintainer può ancora scegliere esplicitamente il percorso developer con
`-DotNetPath <percorso-sdk>`. Non è il percorso adottante e richiede l'SDK compatibile
con `global.json`; non esiste download o fallback automatico verso un SDK host diverso.

Per i codici di preflight e gli errori comuni usare
[troubleshooting.md](troubleshooting.md). I dettagli tecnici del runner sono un
[riferimento di implementazione](../operations/ALPHA-GOLDEN-PATH.md), non un percorso
alternativo.

## Confine della prova

Il pilot usa DevelopmentAuth, CA e materiale esclusivamente sintetici e una chiave
Direct process-local e non attraversa il Local Broker Windows. Non prova installer,
cloud, FSE2, custodia production, stabilità
API, HA/DR o produzione. Il prossimo gate di adozione deve misurare black-box il tempo
da prerequisiti disponibili a `ALPHA_GOLDEN_PATH_PASS`, includendo il cleanup.
