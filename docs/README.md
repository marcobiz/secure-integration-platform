# Indice della documentazione

Questa directory è la fonte di verità architetturale del prodotto. Le decisioni normative sono negli ADR; in caso di conflitto un ADR accettato prevale sui documenti descrittivi, mentre i requisiti di sicurezza restano invarianti salvo ADR esplicito che motivi il cambiamento.

## Ordine di lettura

1. [Sintesi esecutiva](architecture/executive-architecture.md)
2. [Requisiti e criteri di accettazione](requirements/requirements.md)
3. [Assunzioni e questioni esterne](assumptions.md)
4. [Inventario e analisi sanificata degli input](input-analysis.md)
5. [Architettura e confini di fiducia](architecture/system-architecture.md)
6. [Diagrammi di componenti e deployment](architecture/component-diagrams.md)
7. [Diagrammi di sequenza](architecture/sequence-diagrams.md)
8. [Security model](security/security-model.md)
9. [Threat model STRIDE](security/threat-model.md)
10. [Indice ADR](adr/README.md)
11. [Specifica API Gateway](api/gateway-api.md) e [OpenAPI](api/gateway-openapi.yaml)
12. [Protocollo IPC del Local Broker](api/broker-ipc.md)
13. [Schema database](data/database-schema.md)
14. [Specifica Connector](connectors/connector-specification.md), [JSON Schema](connectors/connector-definition.schema.json), [CLI](connectors/connector-cli.md) e [SDK](connectors/connector-sdk.md)
15. [M4 local quick start](operations/M4-QUICKSTART.md)
16. [Architettura M5 e confini provider](architecture/m5-admin-ui-and-provider-boundaries.md)
17. [Piano M5](implementation/M5-IMPLEMENTATION-PLAN.md)
18. [Quick start Admin UI M5](operations/M5-ADMIN-QUICKSTART.md)
19. [Gate Review M5](reviews/M5-GATE-REVIEW.md)
20. [Decisione licenza open source](legal/OPEN-SOURCE-LICENSE-DECISION.md)
15. [Deployment](deployment/deployment-architecture.md) e [Operations](operations/observability.md)
16. [Test strategy](testing/test-strategy.md)
17. [Migrazione legacy](migration/legacy-migration.md)
18. [Piano di implementazione](implementation/implementation-plan.md)
19. [Backlog](implementation/backlog.md)
20. [Definition of Done](implementation/definition-of-done.md)
21. [Matrice di tracciabilità](traceability/requirements-traceability.md)
22. [Gate Review M0/M1](reviews/M0-M1-GATE-REVIEW.md) e [matrice requisito-test-evidenza](reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md)
23. [Runbook matrice live M0/M1](operations/M0-M1-LIVE-MATRIX-RUNBOOK.md)
24. [Architettura implementata M2](architecture/m2-gateway-architecture.md)
25. [Piano M2](implementation/M2-IMPLEMENTATION-PLAN.md), [runbook M2](operations/M2-GATEWAY-RUNBOOK.md), [report M2](testing/M2-IMPLEMENTATION-REPORT.md) e [Gate Review M2](reviews/M2-GATE-REVIEW.md)
26. [Wave 1 typed composed SOAP authenticated dispatch](implementation/WAVE1-TYPED-COMPOSED-SOAP-DISPATCH.md)
27. [Wave 1 authorized typed composed-SOAP request composition](implementation/WAVE1-AUTHORIZED-TYPED-COMPOSED-SOAP-REQUEST.md)

## Deliverable coperti

| Deliverable | Documento |
|---|---|
| Executive architecture | `architecture/executive-architecture.md` |
| System context e trust boundaries | `architecture/system-architecture.md` |
| Diagrammi Broker, Gateway, Connector, Admin e Azure | `architecture/component-diagrams.md` |
| Dodici sequence diagram | `architecture/sequence-diagrams.md` |
| Threat model | `security/threat-model.md` |
| ADR | `adr/` |
| API e IPC | `api/` |
| ER diagram, tabelle, indici e retention | `data/database-schema.md` |
| Connector schema, esempi e plugin contract | `connectors/` |
| Roadmap e work breakdown | `implementation/` |
| Definition of Done | `implementation/definition-of-done.md` |
| Gate Review prima di M2 | `reviews/` |
| Harness live M0/M1 e runbook VM | `../tools/live-matrix/`, `operations/M0-M1-LIVE-MATRIX-RUNBOOK.md` |
| Gateway minimo M2 | `architecture/m2-gateway-architecture.md`, `implementation/M2-IMPLEMENTATION-PLAN.md`, `operations/M2-GATEWAY-RUNBOOK.md`, `testing/M2-IMPLEMENTATION-REPORT.md`, `reviews/M2-GATE-REVIEW.md` |

## Regole di manutenzione

- Ogni modifica di una decisione architetturale aggiorna o sostituisce un ADR.
- Ogni requisito di sicurezza deve avere almeno un test e un riferimento nella matrice di tracciabilità.
- Contratti, esempi e JSON Schema devono evolvere nello stesso change set.
- Non inserire valori provenienti dalle appendici dei report, certificati reali, token, password, chiavi o dati sanitari/personali.
- Gli esempi devono usare esclusivamente host riservati (`example.invalid`) e identità sintetiche.
