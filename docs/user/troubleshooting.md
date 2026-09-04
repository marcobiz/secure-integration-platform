# Troubleshooting

**Pubblico:** adottanti e operatori.
**Stato:** CURRENT. Le azioni seguenti restano sulle superfici supportate; non richiedono
SQL, store diretti o pubblicazione di dati sensibili.

## Pilot locale

| Codice/sintomo | Causa probabile | Azione autorizzata |
|---|---|---|
| `ALPHA_GOLDEN_PATH_DOCKER_UNAVAILABLE` | Docker CLI/Engine assente, fermo o non raggiungibile. | Installare o avviare Docker in modalità Linux containers, quindi ripetere lo stesso `Validate`. Non installare .NET come workaround. |
| `ALPHA_GOLDEN_PATH_DOCKER_COMPOSE_UNAVAILABLE` | Il plugin Compose non è disponibile. | Installare/abilitare Docker Compose supportato e ripetere `Validate`; non usare un orchestratore alternativo. |
| `...COMPONENT=ContainerDotNet...` o `...CHILD_CODE=M5_QUICKSTART_COMMAND_FAILED_DOTNET` | Immagine SDK pinned, package o build container non disponibile. | Verificare rete/cache e disponibilità dell'immagine pinned, poi ripetere manualmente la stessa fase. Non esistono fallback host o retry automatici. |
| `ALPHA_GOLDEN_PATH_DOTNET_HOST_NOT_FOUND` / `...DOTNET_SDK_UNAVAILABLE` | È stato scelto esplicitamente il percorso maintainer `-DotNetPath`, ma il resolver non è utilizzabile o compatibile. | Correggere il percorso developer o omettere `-DotNetPath` per tornare al pilot Docker-first. Non cambiare `global.json` e non usare .NET 8 come fallback. |
| `ALPHA_GOLDEN_PATH_CHILD_EXIT_NONZERO` | Restore, build, container o child process fallito. | Verificare Docker/Compose, rete/cache e spazio; eseguire `-Phase Stop`, poi `Validate` e `Run`. Non ispezionare o modificare il database. |
| Docker non disponibile | Engine fermo o modalità Windows containers. | Avviare Docker con Linux containers e verificare Compose. |
| Run interrotta / risorse residue | Cleanup finale non completato. | Eseguire `./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop`; il comando rimuove solo risorse marker-owned. |
| Manca `ALPHA_GOLDEN_PATH_PASS` | Una verifica o il cleanup non è terminato. | Considerare la run fallita anche se una risposta intermedia era 200; conservare solo diagnostica redatta. |

## FSE2 provisioning

| Codice/sintomo | Significato operativo | Azione autorizzata |
|---|---|---|
| `FSE2_OFFICIALTEST_PLAN_*` o `...PLAN_FILE_INVALID` | Piano fuori schema, troppo grande, duplicato o non protetto correttamente. | Correggere il piano fuori Git usando lo schema chiuso; non aggiungere proprietà o authority runtime. |
| `FSE2_OFFICIALTEST_ADMIN_SESSION_REQUIRED` / `...INVALID` | URL HTTPS, cookie process-local o sessione non validi. | Ottenere una nuova sessione tramite il deployment, nel processo del ruolo corretto. Non mettere il cookie nel piano, nella CLI o nei log. |
| `...ADMIN_REJECTED_401` / `403` | Sessione scaduta o ruolo non autorizzato. | Autenticare lo stesso ruolo previsto e ripetere la stessa fase; non cambiare ruolo per superare RBAC. |
| `FSE2_OFFICIALTEST_INSTALLATION_UNAVAILABLE` / `...AMBIGUOUS` / `...INACTIVE` | Selector non risolve una sola Installation attiva e visibile. | Correggere l’inventario tramite Admin API supportata; non scegliere “la prima” e non interrogare PostgreSQL. |
| `...INSTALLATION_ENVIRONMENT_MISMATCH` | L’asserzione del piano non coincide con l’Environment server-owned. | Fermarsi e correggere il piano/deployment. Non cambiare l’Installation o il binding per forzare il match. |
| `...PROVIDER_AUTHORITY_DRIFT`, `...BINDING_READBACK_DRIFT` | Revisioni/provider/binding non coincidono più. | Rileggere lo stato autorevole, correggere la causa e ripetere il lifecycle; approval vecchie non restano valide. |
| `...APPROVAL_DIGEST_STALE` / `...PUBLISHER_MUST_BE_DISTINCT_APPROVER` | Four-eyes o artefatto exact non valido. | Creare una nuova proposta sullo stato corrente e usare un approvatore distinto. |
| `BGW-PROVISIONING-RATE-LIMITED` / `BGW-RATE-LIMITED` | Quota Admin esaurita, senza retry automatico. | Rispettare l’eventuale `Retry-After` bounded e ripetere lo stesso comando/piano/sessione solo se `retrySafe=true`. |
| `BGW-PROVISIONING-IDENTITY-DRIFT` / `...SERVER-STATE-INVALID` | Stato non monotono o identità cambiata durante la fase. | Fermarsi, rileggere da Admin API e correggere la causa più precoce; non usare force, cleanup distruttivo o SQL. |
| `FSE2_OFFICIALTEST_PROVISIONING_FAILED` | Errore bounded non dettagliato. | Consultare Health e l’audit redatto come Security Administrator; non acquisire response body, stack trace, JWT o certificati. |

## Invocation FSE2

Usare il [runner corrente di validazione e status](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md),
solo con prerequisiti e chiamate OfficialTest autorizzati. I suoi comandi `Audit`,
`Restart` e status hanno esiti e limiti documentati; non costruire payload o chiamate
da test integration, fixture, raw evidence o endpoint copiati.

Il 500 FHIR `generic-error` osservato non ha una causa determinata: non dimostra un
problema di formato, accreditamento o autorizzazione e non autorizza retry automatici
o variazioni speculative. Se manca il workflow, non inventarlo. Un `FOUND` dopo CDA
non prova pubblicazione: vedi la [sintesi capability](../../IMPLEMENTATION_STATUS.md#stato-prodotto).

Se una chiamata autorizzata fallisce, conservare soltanto correlation ID e i campi
diagnostici bounded visibili al Security Administrator (fase, categoria/status bounded,
safe code). Non conservare input CDA, response raw, JWT, header, cookie, chain o P12.

## Quando aprire un problema di prodotto

Aprire un problema di adozione quando il rimedio normale richiede repository knowledge,
SQL, accesso store, ripetuti login, copia manuale di cookie, supporto specialistico o una
sequenza non documentata. Non trasformare il workaround in runbook: descrivere outcome,
fase, safe code e azione che il prodotto avrebbe dovuto offrire.
