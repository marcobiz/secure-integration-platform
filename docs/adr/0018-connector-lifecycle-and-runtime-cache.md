# ADR-0018: Lifecycle, pubblicazione e cache dei Connector

**Stato:** Accepted

## Contesto

ADR-0010 definisce la pipeline dichiarativa, ma non specifica lifecycle, concorrenza, rollback, binding e comportamento della cache necessari al Connector Configuration MVP.

## Decisione

- Una Connector Definition v1 è JSON conforme a Draft 2020-12 e contiene solo riferimenti logici a endpoint e segreti.
- Il lifecycle è `Draft → Validated → Published → Superseded → Retired`. Non esiste uno stato implicito o un bypass di validazione.
- Una versione che è stata Published non può più cambiare definizione, checksum, versione o schema. Il database applica anche un trigger di immutabilità.
- Pubblicare una nuova versione rende la precedente `Superseded`. Il rollback riattiva soltanto una versione `Superseded` già pubblicata; non copia o modifica il JSON.
- Il checksum SHA-256 è calcolato sul JSON UTF-8 canonico. Il dominio numerico v1 ammette solo interi, così la canonicalizzazione resta deterministica e senza ambiguità floating point.
- `row_version` protegge ogni transizione e `publication_revision` serializza pubblicazioni concorrenti sul Connector.
- Endpoint URI e riferimenti provider sono binding per Environment, amministrati server-side e assenti da definizione, runtime request, export e audit.
- Il runtime risolve esclusivamente la versione `Published`. Una cache TTL conserva lo snapshot completo, ma verifica a ogni invocazione uno stamp leggero di pubblicazione. Cambio di stato/revisione, invalidazione locale, corruzione o indisponibilità dello store impediscono l'uso dello snapshot: nessun fallback stale.
- L'Admin API è l'unico confine supportato da CLI e strumenti; non è consentito accesso diretto al database.

## Conseguenze

La revoca/retirement è effettiva anche entro il TTL, il rollback mantiene provenance e checksum, e due publisher non possono vincere in silenzio. Una temporanea indisponibilità PostgreSQL interrompe le nuove invocazioni invece di usare configurazione potenzialmente revocata.

## Alternative escluse

Cache che usa stale-on-error, modifica in-place di Published, rollback tramite nuova copia, URL/secret reference nel payload client, workflow/script arbitrari e accesso CLI diretto al database.
