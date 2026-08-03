# Inventario e analisi sanificata degli input

## Perimetro

La baseline è stata ricavata dai sei documenti presenti in `input-docs/`. I documenti sono trattati come TLP:AMBER+STRICT o equivalenti. Questa sintesi conserva solo pattern architetturali, categorie di finding, protocolli, seam d'integrazione e requisiti di remediation.

Non sono riprodotti:

- password, token, client secret o API key;
- chiavi private, password di certificati o materiale crittografico;
- endpoint operativi non necessari alla progettazione;
- dati personali o sanitari;
- PoC, istruzioni offensive o codice proprietario decompilato.

## Inventario

| Documento | Contenuto utile alla progettazione |
|---|---|
| `CYBERSICUREZZA_WINGESFAR.md` | Segreti vendor e tenant distribuiti, chiavi universali, TLS bypass, log sensibili, updater FTP/HTTP, IPC locali aperti, egress diretto e impersonazione. |
| `REPORT_INFANTIA_PROFIM_v2.md` | Legacy VB6/.NET Framework/COM, certificati embedded, database locali, IPC e autorizzazione client-trusted, script non fidati e remediation AppSec separata. |
| `REPORT_DEVICEHUB_WINDOWS_v2.md` | Canale cloud-to-device, plugin e comandi non autorizzati, filesystem/device access, API localhost, repointing, update non verificato e dipendenze EOL. |
| `REPORT_SICUREZZA_CGM_DRCLOUD.md` | Ecosistema mobile/desktop, Vendor Secret e certificati pubblici, JWT, TLS, API locali, IPC, tenant binding, logging, WebView e supply chain. |
| `Autenticazione Servizi Pubblici.pdf` | Matrice reale di SOAP/REST, Basic+MFA, OAuth2 authorization code/PKCE, mTLS, HMAC, JWT, SAML/WS-Security, smart card e VPN. |
| `architettura_sicurezza_gestionali_sanitari.html` | Consolidamento sanificato di 176 finding e separazione fra controlli comuni, mitigazioni parziali e remediation specifiche. |

## Categorie di causa radice

1. **Vendor Secret distribuiti.** Credenziali e certificati comuni alla software house presenti in binari, configurazioni, installer o log.
2. **Trust client-side.** Tenant, struttura, Installation o Operator accettati come parametri modificabili senza binding server-side.
3. **Protezione locale universale.** Chiavi hardcoded, algoritmi deterministici, cifratura senza autenticazione e credenziali database comuni.
4. **IPC e API locali aperti.** HTTP localhost, Named Pipe, TCP e message bus senza caller identity, operation grants o replay protection.
5. **Comandi remoti eccessivi.** Peer cloud capace di selezionare filesystem, processi, URL, update o periferiche senza capability ristrette.
6. **Trasporto insicuro.** Trust-all TLS, protocolli legacy in chiaro, hostname non validato e fallback HTTP.
7. **Logging e release hygiene.** Token, PIN, credenziali, PII e artefatti di test in log o pacchetti.
8. **Supply chain.** Binari, plugin, script e aggiornamenti senza firma, integrità o anti-rollback.
9. **AppSec fuori piattaforma.** SQLi, XXE, backdoor, IDOR/BOLA server-side, dipendenze obsolete e directory user-writable.

## Protocolli da coprire

- SOAP/XML con Basic Authentication e sessione MFA inserita in header.
- REST/JSON e SOAP/XML protetti da OAuth2.
- Authorization code e PKCE con browser/autenticazione locale e token exchange centrale.
- mTLS con certificato vendor centralizzato o certificato tenant locale/centrale.
- HMAC-SHA256 su messaggi costruiti dal legacy.
- JWT RS256 con claim, issuer, audience e durata vincolati dal Connector.
- SAML 2.0, WS-Security e XML-DSig come moduli compilati.
- Smart card/CNS/token USB e VPN con esecuzione locale.

## Regole di tracciabilità clean-room

- Ogni seam di migrazione registra documento e finding di origine senza includere evidenza sensibile.
- I test sono comportamentali e usano fixture sintetiche.
- Le specifiche ricostruite indicano il livello di certezza: osservato staticamente, verificato in laboratorio o da validare lato server.
- Nessun codice proprietario decompilato viene copiato salvo autorizzazione legale distinta e documentata.

