# M4 local quick start

## Prerequisites

- Docker Engine with Linux containers and Docker Compose;
- .NET SDK pinned by `global.json`;
- PowerShell 7 or Windows PowerShell 5.1.

Azure, cloud accounts, Docker Hub login and real secrets are not required.

## Verified startup

From the repository root:

```powershell
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Validate
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Start
```

The script generates synthetic fixtures under `.artifacts/m4/quickstart`, starts PostgreSQL 18, the migration runner, Gateway, Synthetic Vault and HTTPS/mTLS mock, then uses the CLI to list Connectors and test `sample-secure-service/submit`. The test resolves the Published version, endpoint and secret references exclusively server-side.

## Cleanup

```powershell
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Stop
```

The command removes the containers, network and volume for project `broker-gateway-m4-quickstart`. `.artifacts` is ignored by Git and contains raw synthetic material: do not publish it.

## Expected result

`M4_QUICKSTART_START_PASS` and, after stopping, `M4_QUICKSTART_STOP_PASS`. Any failed prerequisite, health check, CLI call or cleanup terminates with a nonzero exit code.
