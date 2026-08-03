# ADR-0015: Esecuzione locale, centrale e ibrida

**Stato:** Accepted

## Decisione

Ogni operation dichiara `gateway`, `broker` o `hybrid`. `hybrid` ammette solo handoff tipizzati: authorization-code exchange, local signature o local MFA.

## Conseguenze

Vendor Secret forza Gateway; smart card, VPN e chiave non esportabile forzano Broker. Il client non cambia la location. Flussi ibridi ulteriori richiedono ADR e threat analysis.

