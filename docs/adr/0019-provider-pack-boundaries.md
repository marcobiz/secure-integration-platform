# ADR-0019: confini fisici dei provider pack

**Stato:** Accepted

## Contesto

Il Core M4 contieneva tipi e pacchetti Azure in `Gateway.Infrastructure` e nella composition root. La separazione era logica ma non sufficiente a dimostrare che il prodotto open source potesse compilare, essere testato e distribuito senza Azure.

## Decisione

- Le capability sono contratti stretti e separati: secret value retrieval, certificate retrieval, signing/key use, MAC, health e capability discovery. Non esiste una generica `IKms`.
- I contratti vivono in `src/Providers/Abstractions` e non dipendono da SDK cloud.
- Il provider sintetico vive in `src/Providers/Synthetic` ed è parte del Core testabile localmente.
- I provider deployment-specific vivono sotto `packs/deployment/<provider>` e dipendono dal Core, mai il contrario.
- Il Gateway carica un pack opzionale attraverso un contratto provider-neutral e configurazione esplicita. Tipi, URI scheme, credential classes e SDK del provider non attraversano il confine Core.
- Una solution Core, un architecture test e l'export OSS verificano l'assenza di riferimenti provider-specific.
- Il pack Azure è opzionale e resta escluso dall'export OSS finché la strategia di pubblicazione/licenza non viene deliberata.

## Conseguenze

Il Core compila senza pacchetti Azure e può usare il provider sintetico per CI e quickstart. Un deployment pack conserva ownership di autenticazione cloud, parsing dei propri riferimenti e health specifico. L'assemblaggio deployment-specific richiede packaging esplicito e non può essere ottenuto aggiungendo condizioni Azure nella composition root Core.

## Alternative escluse

- Un'interfaccia generica `IKms`, perché nasconde capability e amplia privilegi.
- Riferimenti condizionali ad Azure nel progetto Core, perché non dimostrano indipendenza fisica.
- `#if AZURE`, reflection su tipi Azure nella composition root o fallback automatici, perché rendono il confine ambiguo e non fail-closed.

