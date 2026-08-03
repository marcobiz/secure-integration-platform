# Assunzioni, default e dipendenze esterne

## Default tecnici

- .NET 10 LTS per Local Broker, Gateway e Admin.
- C++20 per C ABI e COM Automation x86/x64.
- PostgreSQL 18 come database operativo.
- Azure App Service for Containers, Azure Key Vault, Managed Identity, Azure Database for PostgreSQL Flexible Server e Bicep.
- Windows 11 e Windows Server 2019/2022/2025 come baseline; Windows 10 22H2 solo in compatibility tier con ESU.
- GitHub Actions come pipeline di riferimento, con script eseguibili anche localmente e senza lock-in nella logica di build.
- REST Secure Layer con API key vendor e mTLS come primo vertical slice sintetico.
- JSON canonico RFC 8785 e JSON Schema Draft 2020-12.

## Target iniziali, non SLA contrattuali

- 50 richieste/secondo sostenute per istanza Gateway.
- 100 richieste concorrenti per istanza.
- 10.000 Installation nel test di scala del registro.
- Payload ordinario massimo 16 MiB; streaming massimo 64 MiB.
- Timeout outbound predefinito 30 secondi e massimo 60.
- Availability target MVP 99,9%.
- Retention audit operativo 90 giorni e amministrativo 365 giorni.

## Decisioni non bloccanti prima del pilot

Lo sviluppo M0-M7 e i Connector sintetici non dipendono da:

- credenziali o certificati reali;
- accesso a servizi sanitari di produzione;
- prodotto legacy pilota definitivo;
- Azure region definitiva;
- volumi commerciali definitivi.

## Input necessari prima del pilot reale

- prodotto e integrazione formalmente selezionati;
- contratti e ambiente di collaudo del servizio esterno;
- matrice Windows della base installata;
- Tenant Entra, Azure region e requisiti di residenza dei dati;
- ownership e custodia dei certificati di code signing;
- processo autorizzato di revoca e rotazione dei vecchi segreti;
- SLO, volumi, retention e requisiti DR contrattuali.

In assenza di questi input si usano i default documentati senza bloccare il vertical slice sintetico.

