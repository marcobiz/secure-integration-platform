# Admin UI M5 in locale

Questa procedura avvia un ambiente di sviluppo locale per esplorare la Admin UI M5. Non è un nuovo gate, non avvia VM e non modifica la configurazione Production.

## Prerequisiti

- Windows con PowerShell 5.1 o successivo;
- Docker Desktop avviato con Linux containers;
- Node.js 22 e npm;
- SDK .NET già bootstrapato nella directory `.dotnet` del repository;
- certificato HTTPS di sviluppo .NET attendibile.

La prima volta, se il launcher segnala `M5_ADMIN_DEV_HTTPS_CERTIFICATE_NOT_TRUSTED`, eseguire dalla root e accettare il prompt di Windows:

```powershell
./.dotnet/dotnet.exe dev-certs https --trust
```

## Avvio

Dalla root del repository:

```powershell
./scripts/dev-admin.ps1
```

In alternativa, da `cmd.exe` o con doppio clic:

```bat
scripts\dev-admin.cmd
```

Il launcher verifica i prerequisiti, avvia solo PostgreSQL 18 tramite Compose, attende la readiness, applica le migration esistenti, applica il seed idempotente, avvia Gateway e Vite e apre il browser. Gli URL sono:

- Admin UI: `https://localhost:5173/admin/`
- Gateway: `https://localhost:5180`
- readiness: `https://localhost:5180/health/ready`

Il target Gateway è definito una sola volta in `src/Admin/Admin.Web/.env.development` e viene letto sia da Vite sia dal launcher.

## Login DevelopmentAuth

La pagina di login offre gli utenti DevelopmentAuth già inclusi nel prodotto: Viewer, Connector Editor, Connector Approver, Operator e Security Administrator. Per esplorare tutte le schermate scegliere **Security Administrator**. Il login crea una vera sessione server-side con cookie Secure/HttpOnly e CSRF; non esiste un percorso allow-all.

DevelopmentAuth e il seed sono entrambi fail-closed fuori da `Development`. Production continua a richiedere OIDC.

## Dati demo

Il seed contiene esclusivamente metadata sintetici e stabili:

- tenant `demo`;
- application `demo-legacy`;
- installation pending;
- Connector `demo-orders`, con una versione `Validated` associata a binding e una versione `Draft`;
- endpoint `https://api.example.invalid/orders`;
- catalog entry logica `demo-api-key`, senza valore segreto;
- grant `submit` e audit metadata-only.

Il provider è quello `InMemory` già consentito esclusivamente in Development/Testing. Non vengono creati API key, token, PFX permanenti o credenziali reali. Il PFX temporaneo esportato dal certificato di sviluppo è conservato sotto `.artifacts` solo mentre i processi sono attivi e viene eliminato al cleanup.

## Stop e reset

Premere `Ctrl+C`. Il launcher arresta Gateway e Vite e rimuove soltanto container e network del progetto Compose `broker-gateway-admin-dev`. Il volume PostgreSQL e i dati demo restano disponibili per l'avvio successivo.

Per eliminare solo il database demo locale e ricrearlo:

```powershell
./scripts/dev-admin.ps1 -Reset
```

`-Reset` non tocca altri container, volumi, evidence o file del repository.

## Smoke test per sviluppatori

Per verificare automaticamente PostgreSQL, migration, health/readiness, proxy, `/admin/auth/me`, navigazione delle superfici M5, seed idempotente e cleanup:

```powershell
./scripts/dev-admin.ps1 -SmokeTest -NoBrowser
```

## Perché prima compariva ECONNREFUSED

`npm run dev` avviava soltanto Vite su `127.0.0.1:5173`; il proxy inoltrava `/admin/auth/*` e `/admin/api/*` a `https://localhost:8443`. Nessun processo di sviluppo veniva però avviato su quella porta: il Compose M5 usa `18443` e non esiste un launch profile ASP.NET che avvii automaticamente Gateway su `8443`. `ECONNREFUSED` indicava quindi correttamente un backend assente.

Ora il proxy development punta a `https://localhost:5180`, lo stesso endpoint su cui il launcher avvia realmente Gateway. Avviare `npm run dev` da solo continua intenzionalmente a non simulare il backend.

## Risoluzione problemi

- **`ECONNREFUSED /admin/auth/me`**: usare `./scripts/dev-admin.ps1`; controllare `.artifacts/m5/admin-dev/gateway.error.log`. Il proxy non nasconde un Gateway assente.
- **PostgreSQL non disponibile**: verificare `docker info`, Linux containers e che `127.0.0.1:15435` sia libero. Il launcher attende l'healthcheck reale.
- **Porta occupata**: chiudere il processo su `5173` o `5180`; il launcher termina con `M5_ADMIN_DEV_UI_PORT_IN_USE` o `M5_ADMIN_DEV_GATEWAY_PORT_IN_USE` senza prendere possesso del processo estraneo.
- **Certificato HTTPS**: eseguire una volta `./.dotnet/dotnet.exe dev-certs https --trust`; non usare bypass TLS nel browser o nel proxy.
- **`node_modules` assente o obsoleto**: il launcher esegue `npm ci --ignore-scripts` quando manca Vite o cambia `package-lock.json`.
- **Database demo da ricreare**: usare `-Reset`; il normale `Ctrl+C` conserva il volume.

