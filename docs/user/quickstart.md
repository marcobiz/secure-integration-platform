# Quick start

**Pubblico:** nuovo adottante.
**Stato:** CURRENT.

## Vuoi vedere il prodotto funzionare?

Usa il [pilot locale Core](local-pilot.md), percorso principale di valutazione:
richiede soltanto Git, PowerShell e Docker Linux/Compose; non richiede .NET SDK, Node,
npm, curl, PostgreSQL, cloud, FSE2, `.env`, SQL, accesso agli store o una CA installata
sull'host. Dalla root del checkout:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Validate
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Run
```

Risultato: una chiamata Direct .NET attraversa il Gateway e un Connector Published,
raggiunge un mock HTTPS/mTLS e torna con risposta sanificata e audit metadata-only.
Il marker finale è `ALPHA_GOLDEN_PATH_PASS`; la run rimuove le proprie risorse.
In caso di interruzione, eseguire `./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop`.

## Vuoi capire il confine Windows / Local Broker?

Il pilot Direct non attraversa il Local Broker. Le
[prove Windows già disponibili](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#prove-windows--local-broker)
sono laboratori storici su Windows Service reale, con prerequisiti dedicati; non sono
un secondo quickstart, un MSI o una nuova qualifica della baseline corrente.

## Vuoi provare FSE2 OfficialTest?

Usa il [pilot corrente di validazione e status](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md).
È un pack opzionale, con SDK .NET sull'host, materiale A1/S1 e accesso OfficialTest già
autorizzati: la promessa Docker-only del Core non si applica a questo percorso.
Il runner gestisce bootstrap locale, enrollment e ruoli; consente VERIFICA e
consultazione, non pubblicazione documentale.

CDA e workflow status dopo riavvio sono qualificati live nei casi osservati; FHIR
rimane non qualificato live (500, causa non determinata). Vedi la
[sintesi delle capability e dei limiti](../../IMPLEMENTATION_STATUS.md#stato-prodotto).

Non sostituire i prerequisiti mancanti con SQL, accesso diretto al catalogo, endpoint copiati
da evidence, test integration o un `curl` costruito a mano.

## Vuoi soltanto esplorare l’Admin UI?

Completa prima il pilot locale, poi usa la
[guida di amministrazione](administration.md). Il quickstart Admin di milestone è un
laboratorio di ispezione, non un secondo percorso di adozione.
