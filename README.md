# Secure Integration Platform

Un gestionale installato sui PC dei clienti deve chiamare servizi esterni, ma distribuire
con il programma le credenziali del fornitore e le relative chiavi private di firma
significa distribuirne anche il controllo. Secure Integration Platform (SIP) separa
l'applicazione che chiede un'operazione dal server che custodisce e usa quelle credenziali.

È pensata per sviluppatori e software house che integrano software Windows, on-premise
o legacy, e per CTO che vogliono governare accessi e integrazioni senza consegnare
segreti esterni a ogni installazione. Il client invoca un'operazione autorizzata;
destinazione, credenziali e firme sono risolte sul server. Non esiste un'API `GetSecret`
per applicazioni, Local Broker o Admin UI.

Per esempio, un gestionale può chiedere «invia questo ordine» a un Connector, cioè una
definizione versionata dell'integrazione. Il server verifica identità e permessi, chiama
il servizio configurato e restituisce una risposta sanificata. Il gestionale non sceglie
un URL arbitrario e non riceve la credenziale del fornitore o la chiave di firma.
L'esempio eseguibile sotto usa un ordine e un servizio interamente sintetici.

> Private preview tecnica, non produzione né certificazione complessiva. Non è un
> proxy universale o un'integrazione automatica per qualsiasi legacy: servono Connector
> e client compatibili. Le identità dei client restano da proteggere; Administrator e
> SYSTEM sull'host sono minacce privilegiate residue. Vedi i [limiti](docs/user/known-limitations.md).

## Provalo subito: Core locale, senza cloud

Da un checkout del repository, servono Git, Docker con Linux containers e Compose, e
PowerShell 5.1 o 7. Questo percorso Core non richiede .NET SDK, Node, npm, curl o
PostgreSQL sull'host: build, tool e sample usano container. Il pilot FSE2 ha
[prerequisiti propri](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md#prerequisiti).

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Validate
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Run
```

Il runner verifica una chiamata Direct .NET → Gateway → Connector Published → mock
HTTPS/mTLS, con risposta sanificata e audit metadata-only. Usa materiale sintetico
per-run e rimuove le proprie risorse; il marker finale è `ALPHA_GOLDEN_PATH_PASS`.
In caso di interruzione:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop
```

[Quick start](docs/user/quickstart.md) · [Procedura completa e marker](docs/user/local-pilot.md) ·
[Troubleshooting](docs/user/troubleshooting.md)

## Tre prove, tre confini

### A. Core sintetico — percorso principale di valutazione

Il [pilot Docker-first](docs/user/local-pilot.md) prova la chiamata autorizzata e la
separazione delle credenziali sul percorso Direct. Non richiede cloud o pack verticali,
non attraversa il Local Broker Windows e non qualifica un servizio esterno.

### B. Windows / Local Broker — il confine per il software installato

Il software Windows comunica via Named Pipe con un Local Broker eseguito come Windows
Service sotto un'identità distinta. Le prove già disponibili verificano autorizzazione
del processo, isolamento tra utenti, ACL e persistenza dopo riavvio; il percorso M3A
collega inoltre il simulatore legacy al Gateway e a un fornitore sintetico.

Sono [evidenze e runbook storici](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#prove-windows--local-broker):
dimostrano quel confine sulle baseline attestate, non una nuova demo pronta all'uso sul
CURRENT. Richiedono un laboratorio Windows dedicato e prerequisiti propri; MSI e
adapter C ABI/COM non sono disponibili come percorso di adozione qualificato.

### C. FSE2 opzionale — evidenza di un'integrazione reale

Il pack per il Fascicolo Sanitario Elettronico 2.0 usa i contratti del Core, senza
introdurre una dipendenza sanitaria nel Core. Il
[pilot corrente di validazione e status](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md)
documenta CDA `VERIFICA` e workflow `FOUND` dopo riavvio qualificati live in OfficialTest.
Le 14 route sono complete offline **nei limiti della specifica congelata**; FHIR non è
qualificato live (HTTP 500, causa non determinata) e la pubblicazione documentale live
non è qualificata. Non è una certificazione complessiva né una qualifica di produzione.

La [sintesi autorevole delle capability](IMPLEMENTATION_STATUS.md) distingue stato
integrato, copertura offline ed evidenze live, senza trasferire qualifiche tra profili.

## Come è composto

- **Local Broker e client .NET:** accesso delle applicazioni installate; il client Direct
  può raggiungere il Gateway senza Broker.
- **Gateway e Connector Runtime:** autorizzazione, esecuzione dell'integrazione e uso
  server-side delle capability di autenticazione, firma e trasporto.
- **PostgreSQL e Admin UI/API:** configurazioni, permessi, approvazione a quattro occhi
  e audit metadata-only. La UI usa soltanto API Admin autenticate same-origin.
- **Synthetic Provider e pack opzionali:** il Core si valuta da solo; provider di
  deployment e integrazioni verticali dipendono dal Core, mai il contrario.

![Sanitized Admin UI dashboard](docs/images/admin-dashboard.png)

## Approfondisci

- [Onboarding guidato Connector](docs/user/guided-connector-onboarding.md) e
  [amministrazione](docs/user/administration.md).
- [Sviluppare un Connector](docs/connector-development/README.md).
- [Architettura](ARCHITECTURE.md) e [confini dell'export Core](OPEN_SOURCE_BOUNDARIES.md).
- [Indice documentale](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/README.md),
  [riferimenti storici](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md) e
  [regole per contributor](https://github.com/marcobiz/secure-integration-platform/blob/main/AGENTS.md).

Segnalare vulnerabilità tramite [SECURITY.md](SECURITY.md), senza pubblicare token,
certificati, payload o risposte raw.
