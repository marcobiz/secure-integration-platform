# Analisi pubblica degli input architetturali

## Perimetro

Le decisioni architetturali pubbliche sono basate sulla documentazione ufficiale dei servizi, su standard pubblici e su fixture sintetiche mantenute nel repository. Valutazioni esterne a questo perimetro non costituiscono input normativi per la specifica pubblica del prodotto.

La documentazione pubblica non deve contenere credenziali, materiale crittografico privato, dati personali o sanitari, endpoint operativi non pubblici o artefatti non necessari alla progettazione.

## Input normativi pubblici

- specifiche ufficiali correnti di FSE 2.0, Sistema TS, VetInfo e dei servizi sanitari regionali pertinenti;
- standard pubblici per SOAP, REST, OAuth 2.0, mTLS, JWT, PKCE, Basic Authentication e gestione delle sessioni;
- fixture e caratterizzazioni sintetiche prive di dati reali;
- requisiti architetturali generici del Connector Runtime, del ciclo di vita dei connector e delle provider abstraction.

## Requisiti architetturali

1. Credenziali, certificati e token outbound sono risolti e gestiti da componenti server-owned tramite provider distinti per secret, certificati e operazioni con chiavi.
2. Identità, tenant, installazione e autorizzazioni sono derivati da stato autenticato lato server e non da parametri client considerati autoritativi.
3. Le operazioni esposte ai client sono limitate da grant espliciti per connector e operation; endpoint e binding delle credenziali restano configurazione server-side.
4. Le chiavi esportabili possono essere custodite centralmente; le chiavi realmente non esportabili richiedono una capability locale controllata senza esporre il materiale privato.
5. Token e riferimenti di sessione sono stato runtime opaco, con durata, rinnovo e invalidazione governati dal connector.
6. Trasporto, egress, logging e audit applicano validazione TLS, minimizzazione dei dati e comportamento fail-closed.
7. Il ciclo di vita dei connector separa definizione, validazione, approvazione, pubblicazione immutabile ed esecuzione.

## Protocolli da coprire

- SOAP/XML con Basic Authentication o riferimenti di sessione quando previsti dalla specifica ufficiale;
- REST/JSON e SOAP/XML protetti da OAuth 2.0;
- Authorization Code con PKCE e interazione dell'utente quando richiesta dal servizio;
- mTLS con certificati risolti tramite provider centrale o capability locale controllata;
- JWT con algoritmo, claim, issuer, audience e durata vincolati dalla definizione del connector.

## Tracciabilità pubblica e caratterizzazione sintetica

- Ogni specifica pubblica dichiara una provenance tra `OFFICIAL_SPEC`, `PUBLIC_STANDARD` e `SYNTHETIC_CHARACTERIZATION`.
- Le fixture descrivono esclusivamente forme di request, response, fault e transizioni di stato sintetiche.
- Una conclusione non sostenuta da una fonte pubblica o da una caratterizzazione sintetica non è normativa per il prodotto pubblico.
- La caratterizzazione sintetica non include dati reali, identificativi operativi, credenziali o materiale crittografico privato.
