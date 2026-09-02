# Amministrazione

**Pubblico:** amministratori e operatori autorizzati.
**Stato:** CURRENT per Admin UI/API integrate; la modalità DevelopmentAuth è soltanto
locale e sintetica.

L’Admin UI comunica esclusivamente con Admin API same-origin autenticate. Non accede a
PostgreSQL, provider o filesystem. Tenant, Installation ed Environment sono autorità
server-side; endpoint e riferimenti provider non sono selezionabili dal runtime caller.

## Ruoli e separazione delle responsabilità

| Ruolo | Compito normale |
|---|---|
| Viewer | Leggere stato non sensibile. |
| Connector Editor | Importare/validare una definition e proporre l’approvazione. |
| Connector Approver | Approvare il checksum esatto; deve essere distinto dal proposer. |
| Security Administrator | Gestire Installation, binding server-owned, grant, audit diagnostico autorizzato e health. |
| Operator | Eseguire test controllati sulle superfici consentite. |

La UI può nascondere azioni non autorizzate, ma RBAC, tenant scope, CSRF, concurrency e
four-eyes sono sempre applicati dal server.

## Ordine canonico di onboarding

Per un nuovo Connector usare la pagina **Onboarding guidato** e la procedura a cinque
azioni in [Onboarding guidato di un Connector](guided-connector-onboarding.md). La pagina
seleziona le autorità server-owned, mostra il ruolo successivo e riprende dallo stato
persistito senza chiedere UUID, checksum o JSON di binding.

```text
deployment/provider bootstrap
→ Environment e Installation enrollment
→ definition validate/import
→ stored validation
→ binding server-owned
→ grant Installation/Connector/operation
→ editor proposal
→ distinct approval
→ publish
→ verify Published/Active
→ una invocation bounded
→ audit metadata-only
```

Il normale percorso usa Admin UI/API o un provisioner supportato e idempotente
`plan → apply → verify`. Non usare SQL, accesso diretto allo store, modifica di righe
Published o valori recuperati dai log.

## Lifecycle del Connector

`Draft → Validated → Published → Superseded → Retired`.

- Una versione Published è immutabile.
- Pubblicare una nuova versione rende Superseded quella precedente.
- Il rollback riattiva una versione Superseded già pubblicata; non copia o modifica JSON.
- Ogni mutazione usa la row/publication revision osservata. Un conflitto richiede nuovo
  read-back, non un force.
- Una modifica del binding crea una nuova revisione e invalida approval precedenti.

## Binding, provider e grant

Una definition contiene solo nomi logici. L’amministratore sceglie per Environment
endpoint HTTPS e risorse provider dai cataloghi server-owned; il browser invia soltanto
identificatore, revisione e checksum come assertion, mentre il server risolve l’autorità
effettiva. Secret retrieval, certificato client,
signing e health sono capability separate. Il browser e il client runtime non ricevono
secret value, chiavi private, P12, provider locator o URL arbitrari.

Il grant è deny-by-default e lega una Installation a Connector/operation. L’Environment
non è scelto dal grant o dal client: deriva dall’Installation autenticata.

## Audit, health e recovery

- `/health/live` verifica il processo; `/health/ready` include dipendenze necessarie.
- Audit conserva metadata bounded, non payload, credenziali, cookie, header o response
  raw.
- In locale la pagina **Audit** è `/admin/audit`.
- Su 429 o sessione scaduta, leggere lo stato server-side e ripetere la sola azione
  dichiarata retry-safe. Non attendere in loop o rifare l’intero onboarding.
- Un provider/binding drift rende stale l’autorità Published prima di firma/rete; prima
  si corregge la causa autorevole, poi si ripubblica secondo lifecycle.

Per esplorare l’UI dopo il [pilot locale](local-pilot.md), il laboratorio Admin può essere
avviato con `./tools/m5/Invoke-M5Quickstart.ps1 -Phase Start` e chiuso con `-Phase Stop`.
È un ambiente sintetico di ispezione, non un secondo pilot canonico né una configurazione
production. Per le azioni specifiche FSE2 usare
[fse2-officialtest.md](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-officialtest.md).
