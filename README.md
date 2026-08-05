# Secure Integration Platform

Core provider-neutral di una piattaforma di integrazione sicura per software on-premise e legacy.

La piattaforma rimuove segreti hardcoded e credenziali distribuite con il minor numero possibile di modifiche ai prodotti esistenti. Il core è vendor-neutral; il sanitario costituisce il primo caso d'uso e il primo Connector Pack.

## Stato

M0–M2 e il product gate M3A sono conclusi. M4 Connector Configuration MVP è implementato sul branch dedicato e in gate. M3B resta una qualificazione separata dell'Azure Deployment Pack. Lo stato verificabile è in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

## Quick start M4 senza Azure

Con Docker Linux containers, .NET SDK e PowerShell:

```powershell
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Validate
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Start
./tools/m4/Invoke-M4Quickstart.ps1 -Phase Stop
```

Avvia PostgreSQL 18, Gateway, Synthetic Vault e mock HTTPS/mTLS, quindi verifica tramite CLI il Connector Published `sample-secure-service`. Dettagli: [M4 local quick start](docs/operations/M4-QUICKSTART.md).

## Build e test

Su Windows PowerShell, dalla root:

```powershell
.\eng\build.ps1
.\eng\test.ps1
.\eng\validate-docs.ps1
.\eng\scan-secrets.ps1
.\eng\generate-sbom.ps1
```

La toolchain è fissata da `global.json`; se presente, gli script preferiscono l'SDK repository-local in `.dotnet`.

## Documentazione

L'indice completo e l'ordine di lettura sono in [docs/README.md](docs/README.md).

I documenti sotto `input-docs/` sono riservati e costituiscono materiale sorgente. Non devono essere copiati in artefatti pubblici o riprodotti nella documentazione derivata con segreti, dati personali o PoC.

## Principi invarianti

- Nessun Vendor Secret nel legacy o nel Local Broker.
- Nessun endpoint generico per ottenere segreti o invocare URL arbitrari.
- Tenant e Installation derivati dall'identità autenticata, non da parametri client.
- Operazioni locali protette dal Local Broker sotto una service identity Windows dedicata.
- Configurazioni Connector validate, versionate, Published immutabili e reversibili.
- Il Local Broker non è una difesa completa contro un amministratore locale o SYSTEM.
- Secure Layer è il percorso di migrazione iniziale; Managed Connector si adotta quando porta riuso concreto.
