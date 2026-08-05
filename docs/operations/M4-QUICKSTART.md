# M4 local quick start

## Prerequisiti

- Docker Engine con Linux containers e Docker Compose;
- .NET SDK fissato da `global.json`;
- PowerShell 7 o Windows PowerShell 5.1.

Non servono Azure, account cloud, Docker Hub login o segreti reali.

## Avvio verificato

Dalla root del repository:

```powershell
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Validate
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Start
```

Lo script genera fixture sintetiche sotto `.artifacts/m4/quickstart`, avvia PostgreSQL 18, migration runner, Gateway, Synthetic Vault e mock HTTPS/mTLS, quindi usa la CLI per elencare i Connector e testare `sample-secure-service/submit`. Il test risolve versione Published, endpoint e riferimenti secret soltanto server-side.

## Cleanup

```powershell
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Stop
```

Il comando rimuove container, network e volume del progetto `broker-gateway-m4-quickstart`. `.artifacts` è ignorata da Git e contiene materiale sintetico raw: non pubblicarla.

## Esito atteso

`M4_QUICKSTART_START_PASS` e, dopo lo stop, `M4_QUICKSTART_STOP_PASS`. Qualsiasi prerequisito, health check, CLI call o cleanup non riuscito termina con exit code non zero.
