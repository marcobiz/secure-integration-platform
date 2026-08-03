# Security model

## Obiettivi di protezione

1. Impedire l'estrazione e la distribuzione dei Vendor Secret.
2. Limitare ogni compromissione locale a una singola Installation.
3. Impedire uso del Local Broker da Application non autorizzate.
4. Impedire impersonazione cross-Tenant/cross-Installation.
5. Impedire al client di trasformare il Gateway in proxy, signer o secret oracle.
6. Proteggere confidenzialità e integrità di dati e chiavi locali contro copia offline.
7. Fornire revoca, rotazione, audit e provenance degli artefatti.

## Classificazione e collocazione dei segreti

### Vendor Secret

Sempre Gateway + Azure Key Vault. Il runtime ottiene il valore solo dopo autenticazione, grant e risoluzione della ConnectorVersion. Il valore non compare in response, exception, audit o cache persistente.

### Tenant Secret

- `broker`: quando la risorsa è locale, la chiave non è esportabile o esiste una VPN tenant.
- `vault`: quando il Gateway può eseguire centralmente.

La posizione è parte della specifica Connector e non è controllata dal client.

### Operator Secret

PIN, OTP, credenziali personali e smart-card interaction restano locali e in memoria. Persistenza richiede requisito, threat analysis e consent espliciti.

### Session Secret

- Gateway: access/refresh token nel Vault; al client solo `sessionRef` opaco.
- Broker: memoria con TTL o DPAPI se il protocollo richiede persistenza locale.
- Legacy: compatibilità temporanea esplicita, auditata e con piano di dismissione.

### Local Data Key

Random 256 bit, per Installation e versione. Wrapping DPAPI CurrentUser; cifratura AES-256-GCM. Non restituita al legacy.

## Local Broker controls

- Virtual service account e service SID dedicati.
- ACL restrittive su pipe, ProgramData e CNG keys.
- Application manifest in area service-only.
- Identità composita: Windows SID, registration, path, publisher e hash opzionale.
- Frame e payload limits, timeout, cancellation, nonce e sequence.
- Autorizzazione per singola operation e logical secret reference.
- `GetSecret` assente; compatibility reveal separato e disabilitato.
- Audit locale redatto e health diagnostics senza valori sensibili.

## Gateway controls

- Certificato e SPKI per Installation, stato controllato a ogni richiesta con cache breve.
- Firma ECDSA su timestamp, nonce, method/path e body hash.
- Tenant/Application derivati dal registry.
- Grants server-side e ConnectorVersion Published.
- Secret binding logici risolti dal server.
- Endpoint, method, path, header e content type configurati.
- SSRF protection sull'IP effettivamente connesso, non solo sulla stringa URI.
- Retry solo idempotente; redirect disabilitati.
- Session secret nel Vault e payload non persistiti.

## Enrollment e credenziali Installation

- Activation code casuale ≥128 bit, TTL 15 minuti, monouso e massimo 5 tentativi.
- Database: HMAC del codice; pepper nel Vault.
- Challenge TTL 5 minuti e proof-of-possession.
- ECDSA P-256 non esportabile in Windows CNG.
- Certificate lifetime 90 giorni, renewal window 30 e overlap 7.
- Revoca immediata e propagation cache ≤30 secondi.
- Reinstallazione genera nuova chiave; clonazione non autorizza automaticamente un host.

## Egress e SSRF

- Solo HTTPS in produzione, salvo Connector locale esplicitamente approvato ed eseguito dal Broker.
- Host e port definiti nella ConnectorVersion/Environment.
- Path template con parametri percent-encoded e regex/length constraints.
- Blocco IP literal, loopback, private, link-local, multicast e cloud metadata.
- DNS risolto prima della connessione e ricontrollato a ogni nuova connessione.
- Hostname/SNI originali preservati.
- Nessun redirect; proxy solo environment-level.
- Request/response/decompression limits.
- Header sensibili costruiti dal runtime e non sovrascrivibili dal client.

## XML e JSON

- DTD ed external entities disabilitate.
- Limiti di byte, profondità, nodi e attributi.
- Schema validation quando disponibile.
- XML-DSig con riferimento ID univoco e protezione signature wrapping.
- Canonicalization definita dal modulo, mai client-selected.
- JSON con depth/property/string limits e `additionalProperties: false` nei contratti.

## Logging, audit e privacy

Campi ammessi: correlation, trace, connector, operation, tenant, installation, result, duration, external status category e versioni.

Campi vietati: payload completi, Authorization/Cookie, token, password, PIN, key material, private certificate, OTP e PII non necessaria.

La redaction è strutturale e avviene prima della serializzazione. Regex/dictionary redaction è una difesa supplementare. Gli Operator identifier in audit sono opachi o pseudonimizzati.

## Supply chain

- Lock file e toolchain pinned.
- Secret, dependency, SAST e container scanning.
- SBOM SPDX e CycloneDX.
- Binari/MSI Authenticode, package e plugin CMS-signed, container Cosign-signed.
- Release manifest con SHA-256, versioni, provenance e compatibilità.
- Plugin caricati solo dalla directory protetta all'avvio.
- Nessun artifact di test, debug secret o dato reale nei release package.

## Rischi dichiarati

- Amministratore locale/SYSTEM può sostituire o ispezionare il Broker.
- Plaintext necessario all'operazione esiste temporaneamente in RAM.
- Un plugin in-process firmato ma malevolo ha piena capacità nel Gateway.
- Compromissione Gateway/Vault richiede incident response e rotazione esterna.
- La piattaforma limita le capability del legacy compromesso ma non ne garantisce l'integrità.

