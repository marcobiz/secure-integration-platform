# ADR-0009: Plugin model

**Stato:** Accepted

## Decisione

Plugin .NET compilati, in-process, caricati solo all'avvio e distribuiti dalla pipeline. Manifest, hash SHA-256, firma CMS, publisher allowlist e compatibilità dichiarata. Nessun upload dalla UI.

## Conseguenze

Implementazione e operations restano semplici, ma un plugin malevolo equivale a Gateway compromesso. Il contratto fornisce servizi ristretti, senza promettere sandbox. Un worker isolato sarà valutato solo con casi third-party reali.

## Alternative escluse

Script, assembly dalla UI e hot-loading sono vietati; process isolation obbligatorio nell'MVP sarebbe costo senza requisito dimostrato.

