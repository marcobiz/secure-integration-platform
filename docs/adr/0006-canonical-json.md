# ADR-0006: JSON canonico

**Stato:** Accepted

## Decisione

JSON Schema Draft 2020-12 per validation e RFC 8785 per canonicalizzazione/checksum. YAML solo import/export, convertito e validato; custom tag e costrutti eseguibili vietati.

## Conseguenze

Diff, checksum, firma e promozione sono deterministici. Numeri e Unicode devono seguire rigorosamente RFC 8785. Le versioni pubblicate conservano JSON canonico immutabile.

## Alternative escluse

YAML come source of truth introduce parsing ambiguo; schema relazionale puro rende rigida l'evoluzione dei Connector.

