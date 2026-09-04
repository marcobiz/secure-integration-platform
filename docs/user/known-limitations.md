# Limitazioni note

**Pubblico:** valutatori, amministratori e decisori.
**Stato:** CURRENT.

## Pilot locale e private preview

- È una prova sintetica locale, non un installer, una release stabile o una qualifica di
  produzione.
- La chiave del client Direct di esempio è process-local; un consumer reale richiede un
  key store protetto/non esportabile appropriato.
- DevelopmentAuth, CA, provider e mock sono soltanto per laboratorio.
- Il runner non riprende a metà: dopo un’interruzione esegue cleanup ownership-checked e
  una nuova run.
- Cloud live, MSI, adapter C ABI/COM, HA/DR, restore/load/soak, pentest e firma artefatti
  non sono qualificati.

## FSE2

La [sintesi autorevole delle capability](../../IMPLEMENTATION_STATUS.md#stato-prodotto)
separa le 14 route complete offline nei limiti della specifica congelata dai soli casi
live qualificati: CDA `VERIFICA` e workflow `FOUND` dopo riavvio. Il
[pilot corrente](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md)
è opzionale e non è un prerequisito del Core.

- FHIR `VERIFICA` non è qualificato live: upstream 500 / Gateway 502 `generic-error`,
  causa non determinata. Non dedurre un problema di formato o accreditamento.
- La pubblicazione documentale live non è qualificata. Il runner consente soltanto
  VERIFICA e consultazione; pubblicare una configurazione Connector non pubblica un
  documento. `FOUND` non dimostra completamento clinico o pubblicazione.
- Lo status mapper scarta intenzionalmente il contenuto non tecnico di
  `transactionData[]` e accetta solo tipi/esiti/timestamp bounded. La correlazione è
  PostgreSQL durevole per restart e scale-out, senza dati clinici.
- Human Actor, callback inbound, direct FHIR publication confermata, accreditamento,
  custody production, monitoraggio generale e produzione sono fuori scope.
- Il runner distribuito gestisce bootstrap locale, enrollment e sessioni di ruolo,
  riusando il provisioner resumable. Richiede SDK .NET host, accesso OfficialTest,
  materiale A1/S1 già predisposto e configurazione organizzativa esterna: non è il
  percorso Docker-only del Core, non importa materiale né crea account esterni.
- Il [vecchio profilo validate-only](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-officialtest.md)
  conserva le proprie qualifiche e versioni Published immutabili; non trasferisce
  automaticamente la qualifica al profilo `fse2-organization-current-spec@1.0.0`.

## Windows / Local Broker

Le [evidenze M0/M1 e M3A](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#prove-windows--local-broker)
provano il confine su Windows Service reale nelle baseline storiche, non un installer
o una demo adopter-facing corrente. Il pilot Core Direct non esercita quel percorso.
Gli adapter C ABI/COM non sono qualificati; Administrator e SYSTEM restano minacce
privilegiate residue, non soggetti completamente isolati dal Broker.

## Regola di adozione

Se onboarding, recovery o test ordinari richiedono intervento specialistico, accesso
diretto agli store, SQL, conoscenza dei test o sequenze inventate, l’esperienza di
adozione è fallita. Il rimedio è una modifica bounded di prodotto/UX o una precondizione
esterna esplicita, non ulteriore conoscenza obbligatoria dell’operatore.
