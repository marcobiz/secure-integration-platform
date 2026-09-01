# Documentazione

Questo indice separa le procedure CURRENT dai riferimenti tecnici e dalla storia. Un
adottante non deve leggere l’intera repository per trovare il percorso supportato.

## CURRENT — scegli il pubblico

| Pubblico | Entry point | Autorità |
|---|---|---|
| Adottante / operatore | [Guida utente](user/README.md) | Procedure CURRENT per quickstart, pilot locale, FSE2, amministrazione, troubleshooting e limiti. |
| Sviluppatore Connector | [Connector development](connector-development/README.md) | Contratto minimo, binding server-owned e golden path di prima chiamata. |
| Maintainer / agente interno | [Documentazione interna](internal/README.md) | Stato, regole di scope, semplicità e review. |
| Architettura / security | [ARCHITECTURE.md](../ARCHITECTURE.md), [ADR](adr/README.md), [security model](security/security-model.md), [threat model](security/threat-model.md) | Decisioni e confini; non sono runbook di adozione. |
| API / contratti | [Gateway API](api/gateway-api.md), [OpenAPI](api/gateway-openapi.yaml), [Connector specification](connectors/connector-specification.md), [schema JSON](connectors/connector-definition.schema.json) | Contratti eseguibili; non forniscono sequenze operative mancanti. |
| Stato e tracciabilità | [dashboard](../IMPLEMENTATION_STATUS.md), [matrice requisiti-test](traceability/requirements-traceability.md) | Stato CURRENT e mapping di evidence. |

## Percorsi utente supportati

1. [Prova il prodotto](user/quickstart.md).
2. [Esegui il solo pilot locale canonico](user/local-pilot.md).
3. [Amministra Connector, binding, grant e audit](user/administration.md).
4. [Valuta il pilot FSE2 OfficialTest e i suoi prerequisiti esterni](user/fse2-officialtest.md).
5. [Risolvi un errore senza SQL o accesso agli store](user/troubleshooting.md).

## Riferimenti CURRENT

Sono CURRENT come riferimenti, non come ordine di lettura per l’adottante:

- `docs/adr/` per decisioni Accepted;
- `docs/api/`, `docs/connectors/connector-specification.md` e
  `docs/connectors/connector-sdk.md` per contratti pubblici;
- `docs/architecture/` eccetto il documento M2 esplicitamente storico;
- `docs/data/database-schema.md`, `docs/requirements/requirements.md` e
  `docs/testing/test-strategy.md` per maintainer e reviewer;
- `docs/implementation/0.1.0-alpha-scope.md`, `implementation-plan.md`, `backlog.md` e
  `definition-of-done.md` come pianificazione interna, subordinata alla dashboard.

I documenti non inclusi in questi gruppi non sono procedure CURRENT. Prima di usarli,
consultare l’[indice storico](history/README.md); i documenti stale o di target restano
non autoritativi finché non vengono riclassificati esplicitamente.

## HISTORICAL

L’[indice storico](history/README.md) classifica i 53 piani, report, review e runbook di
milestone individuati dall’audit. I file non sono ancora spostati in massa: i path
rimangono stabili, ma non devono essere usati per ricostruire lo stato o inventare una
procedura.

## Regole di manutenzione

- Ogni pagina operativa dichiara pubblico, stato e risultato supportato.
- Una sola pagina possiede la sequenza di ciascun pilot; le altre la linkano.
- OpenAPI/schema/migration/test restano autorità eseguibili, ma non sostituiscono passaggi
  operativi mancanti.
- Le guide non contengono SHA di evidence, diari di PR, dettagli del laboratorio, P12,
  token, identificatori reali, endpoint riservati o risposte raw.
- Un problema ripetuto in due Connector è un problema del workflow condiviso, non una
  ragione per duplicare runbook verticali.
