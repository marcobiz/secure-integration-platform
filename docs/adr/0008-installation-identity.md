# ADR-0008: Identità e mTLS per Installation

**Stato:** Accepted

## Decisione

Il Broker genera una chiave ECDSA P-256 CNG non esportabile e un certificato ClientAuth per Installation. Enrollment mediante activation code monouso e proof-of-possession. Gateway registra hash SPKI/certificato, usa mTLS e richiede inoltre firma del request envelope.

Durata certificato 90 giorni, rinnovo da 30 giorni prima e overlap massimo 7 giorni.

## Conseguenze

Non serve una CA complessa nell'MVP; la fiducia è registry-backed. La validazione applicativa è obbligatoria dietro App Service. Reinstallazione genera nuova chiave e richiede enrollment.

## Alternative escluse

API key comune è vietata; certificato vendor condiviso non identifica Installation; CA enterprise completa è rinviata finché non necessaria.

