# Runbook M2 — Gateway minimo

## Prerequisiti

- .NET SDK indicato da `global.json`;
- PostgreSQL **18.x** per la prova RLS reale;
- Docker per build/smoke del container;
- per produzione: Azure Key Vault HTTPS e Managed Identity con accesso ai soli secret
  referenziati;
- certificati e chiavi esclusivamente sintetici negli ambienti di test.

## Build e test locali

```powershell
Set-Location C:\Codice\broker-gateway
.\eng\build.ps1 -Configuration Release
.\eng\test.ps1 -Configuration Release
.\eng\validate-docs.ps1
.\eng\scan-secrets.ps1
```

Senza `GATEWAY_POSTGRES_ADMIN_CONNECTION` il test PostgreSQL reale viene saltato per
mancanza dell'infrastruttura esterna; non costituisce evidenza RLS. In un database di
test dedicato PostgreSQL 18:

```powershell
$env:GATEWAY_POSTGRES_ADMIN_CONNECTION = '<connection string amministrativa del DB di test>'
.\.dotnet\dotnet.exe test .\tests\integration\Gateway.Integration.Tests\Gateway.Integration.Tests.csproj -c Release
Remove-Item Env:GATEWAY_POSTGRES_ADMIN_CONNECTION
```

Il job `gateway-postgresql-18` della CI configura questa variabile contro un service
container effimero e deve risultare verde per chiudere M2.

## Migration esplicita

Usare una identità di deployment separata dal runtime:

```powershell
$env:GATEWAY_MIGRATION_CONNECTION = '<connection string migration owner>'
.\.dotnet\dotnet.exe run --project .\src\Gateway\Gateway.Migrations\Gateway.Migrations.csproj -c Release -- apply
Remove-Item Env:GATEWAY_MIGRATION_CONNECTION
```

Il runner registra nome e SHA-256. Se il contenuto di una migration già applicata è
cambiato, termina con errore. M2 è additiva: il rollback applicativo consiste nel
ripristino dell'immagine precedente; non è previsto un down-script distruttivo.

## Avvio Development con Docker Compose

Generare valori sintetici solo per la sessione e non salvarli:

```powershell
$env:GATEWAY_LOCAL_DB_PASSWORD = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
$env:GATEWAY_LOCAL_ACTIVATION_HMAC_KEY = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
docker compose -f .\deploy\docker-compose.m2.yml up --build -d
Invoke-RestMethod http://127.0.0.1:8080/health/live
Invoke-RestMethod http://127.0.0.1:8080/health/ready
docker compose -f .\deploy\docker-compose.m2.yml down
Remove-Item Env:GATEWAY_LOCAL_DB_PASSWORD,Env:GATEWAY_LOCAL_ACTIVATION_HMAC_KEY
```

Il compose esegue un container migration one-shot e avvia il Gateway solo dopo il suo
completamento. Il processo Gateway non migra mai il DB all'avvio. Il compose è
Development e non dimostra Managed Identity o Key Vault live.

## Configurazione produzione

Configurare tramite provider protetto, mai in `appsettings.json`:

- `ConnectionStrings__GatewayDatabase`: login membro di `gateway_runtime`;
- `Gateway__Provider__Kind`: `ExternalPack`;
- `Gateway__Provider__Endpoint`: endpoint HTTPS del provider;
- `Gateway__Provider__ClientIdentity`: identità opzionale interpretata esclusivamente dal pack;
- `Gateway__ActivationHmacSecretReference`:
  `keyvault://<vault>.vault.azure.net/<secret>[/<version>]`;
- `Gateway__Operations__<n>__*`: catalogo allowlisted; endpoint HTTPS, auth e riferimenti
  Vault sono configurazione server-side.

Con ambiente diverso da Development/Testing, l'avvio fallisce se database, Vault o
activation HMAC reference mancano. Terminare TLS a un ingress fidato oppure configurare
Kestrel HTTPS; non fidarsi di header di certificato inoltrato senza il middleware e la
rete trusted previsti dal deployment Azure.

## Verifiche operative

1. `/health/live` deve rispondere 200 se il processo è vivo.
2. `/health/ready` deve rispondere 200 soltanto con registry e provider secret pronti.
3. Verificare che il container esegua come utente non-root e filesystem read-only.
4. Verificare nei log solo code/correlation metadata; nessun payload, header auth,
   certificate DER, activation code o vault reference.
5. Una revoca deve produrre `BGW-INSTALLATION-REVOKED` prima di DNS/Vault/HTTP.
6. Errori pubblici devono essere `application/problem+json` sanificati.

## Diagnostica e rollback

- readiness DB non verde: verificare schema migration, membership `gateway_runtime` e
  connettività; non elevare il ruolo runtime a owner/superuser;
- Vault non verde: verificare Managed Identity, host allowlisted e RBAC del singolo
  Vault; non sostituire con secret in file;
- egress negato: controllare operation catalog e DNS; non disabilitare i controlli IP;
- rollback: fermare nuova immagine e ridistribuire quella precedente. La migration M2
  resta presente perché è additiva; qualsiasi rollback dati richiede change approvato.
