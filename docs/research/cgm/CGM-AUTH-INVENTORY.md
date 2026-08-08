# CGM authentication inventory

## Metodo di conteggio

I conteggi sono **minimi confermati** sulle 38 seam: una seam può usare più primitive. Un profilo compilato ma non registrato non aumenta il numero. “Confirmed current” significa che la funzione rimane richiesta e la primitiva è confermata da fonte ufficiale o da un profilo operativo corrente; non significa che il meccanismo legacy vada copiato.

## Auth gap recomputation

| Primitive | # integration seam actually using it | Seam principali | Confirmed current | SIP mapping | Priority |
|---|---:|---|---|---|---|
| Basic username/password | 9 | W-01, W-04, W-06, W-16, W-17, W-19..W-21, D-01 | Sì, ma MFA evolve alcuni profili | `SUPPORTED` | P0 |
| PIN/sessione/MFA opaca | 8 | W-01, W-03, W-04, W-06..W-08, D-01, D-03 | Sì per ricetta SSN/SAR | `SUPPORTED` per sessione; UI challenge da profilare | P0 |
| Bearer token | 11 | W-02, W-05, W-11, W-12, W-15, W-19..W-22, D-02, D-05 | Sì | `SUPPORTED` | P0 |
| OAuth authorization code | 4 | W-02, W-09, W-11, D-02 | Sì per i profili osservati | `SUPPORTED` baseline | P0 |
| PKCE | 2 legacy attive; 1 target nazionale aggiuntivo | W-11, D-05; target W-15 | Sì per FVG/Liguria e target VetInfo da accreditare | `MISSING` | P0 |
| OAuth client credentials | 3 | W-05, W-22, D-04 | Sì nei profili osservati | `MISSING` | P0 |
| OAuth resource-owner password grant | 1 | W-15 | No come target raccomandato | `SHOULD_NOT_COPY_LEGACY` | P0 remove |
| mTLS | 10 | W-03, W-05, W-07, W-10, W-12..W-14, W-17 opzionale, D-08, D-11 | Sì in più profili e GTW | `SUPPORTED` one-shot; lifecycle cert da completare | P0 |
| JWT RS256 | 3 | W-11, W-13, D-11 | Sì, GTW ufficiale incluso | `SUPPORTED`; dual-token orchestration `SMALL_EXTENSION` | P0 |
| Dual JWT / dual certificate binding | 2 | W-13, D-11 | Sì per GTW; regionale da accreditare | `SMALL_EXTENSION` | P0 |
| SAML 2.0 assertion | 4 | W-03, W-10, W-14, D-08 | Corrente per i profili XDS/legacy finché accreditati | `MISSING` | P1 |
| WS-Security | 5 | W-03, W-07, W-10, W-14, D-08 | Corrente per i profili SOAP osservati | `MISSING` | P1 |
| HMAC-SHA256 | 1 | W-06 | `NEEDS_CHARACTERIZATION` sul profilo corrente | `MISSING` | P1 |
| XML-DSig / PKCS#7 | 1 | W-07 | Sì se SIST mantiene il profilo | `MISSING` | P1 |
| Smartcard/CNS + PIN per operazione | 1 obbligatoria; 2 usi opzionali | W-07; W-17 e W-20 opzionali | Sì per Puglia osservata; altri opzionali | `MISSING`, Broker locale | P1 |
| RSA/PIN proprietary encryption | 1 | Supporto Piemonte associato a W-08 | `NEEDS_CHARACTERIZATION` | `SMALL_EXTENSION` nel profilo, non primitive generale | P2 |
| Browser/app callback | 4 | W-02, W-09, W-11, D-05 | Sì | `SUPPORTED` come challenge; hardening callback necessario | P0 |
| VPN locale | 1 | W-07 | Sì nel profilo osservato, produzione da caratterizzare | `MISSING`, Broker/network capability | P1 |

### Risultato

Le primitive realmente mancanti che meritano implementazione sono **sette**:

1. PKCE;
2. OAuth client credentials;
3. SAML assertion;
4. WS-Security;
5. HMAC;
6. XML-DSig/PKCS#7 via key operation;
7. smartcard/CNS+PIN come capability Broker controllata.

La VPN è un gap di trasporto locale separato, non una primitiva di autenticazione. Dual-JWT è una piccola estensione di primitive già presenti. Il password grant VetInfo è un gap di migrazione, non una feature da aggiungere. La cifratura RSA/PIN regionale resta nel profilo e non giustifica un framework generale finché non è caratterizzata.

## Proprietà e destinazione dei secret

| Secret type osservato | Ownership | Storage location class | Scope | Rotation osservabile | Target SIP | Provenance |
|---|---|---|---|---|---|---|
| Username/password farmacia | Pharmacy | Config/file/parametro legacy | Per pharmacy/installazione | Manuale o non osservata | `ISecretProvider` | `LEGACY_CONFIG` |
| PIN operatore o session ID | Operator | Input utente, memoria o file legacy | Per operatore/sessione | Sessione/expiry esterno | User interaction + opaque runtime state | `LEGACY_CODE_WINGESFAR` |
| Client ID/secret OAuth | Software-house/product | Config o risorsa applicativa | Shared product o profile | Non affidabile nel corpus | `ISecretProvider`; mai nel client | `LEGACY_CONFIG` |
| Bearer/access/refresh token | Sessione runtime | Memoria e, in alcuni legacy, disco | Per sessione/utente | Expiry/refresh | Gateway ephemeral encrypted cache | `LEGACY_CODE_WINGESFAR`, `LEGACY_CODE_DRCLOUD` |
| PFX e password PFX | Pharmacy, software-house o regional | File/config/store Windows/app resource | Shared o per pharmacy | Scadenza certificato; rotazione non automatica provata | `ICertificateProvider` + `IKeyOperationProvider` | `LEGACY_CONFIG` |
| Certificato non esportabile/smartcard | Operator/pharmacy | Smartcard, token USB, store locale | Per operatore/pharmacy | Lifecycle del dispositivo | Broker/local key operation | `LEGACY_CODE_WINGESFAR` |
| HMAC key | Pharmacy o product, da confermare | Config legacy | `UNKNOWN` | Non osservata | `IKeyOperationProvider` o narrow MAC provider | `LEGACY_CONFIG`, `UNKNOWN` |
| Shared signing key | Software-house/product | App/config/servizio firma | Shared product/profile | Non osservata | Central `IKeyOperationProvider` con segregazione tenant | `LEGACY_CODE_DRCLOUD` |
| Function/API key mediatore | Product | Config/app | Shared product | Non osservata | `ISecretProvider`, solo se si mantiene il mediatore | `LEGACY_CODE_WINGESFAR` |

I valori sono intenzionalmente omessi: `[REDACTED-SECRET]`, `[REDACTED-CERTIFICATE]`, `[REDACTED-TOKEN]`.

## Piano di migrazione dei secret

| Legacy | Target | Regola |
|---|---|---|
| Password | `ISecretProvider` | Reference server-owned, scope farmacia/installazione, rotazione auditata |
| PFX esportabile | `ICertificateProvider` + `IKeyOperationProvider` | Il connector chiede uso/firma, non legge bytes o password |
| Certificato non esportabile | Broker/local capability | L'operazione privata rimane locale; risultato firmato torna al Gateway |
| Shared software-house signing key | Central `IKeyOperationProvider` | Isolamento per product/profile, policy e audit fail-closed |
| OAuth access/refresh token | Gateway runtime ephemeral cache | Cifrato, expiry e audience verificati, mai restituito al caller |
| MFA/session reference | Opaque runtime state | Il client vede solo challenge/result e non può riusare il token grezzo |
| HMAC | Narrow key/MAC operation | Nessuna API generale `GetSecret`; input e algoritmo allowlisted |

## Negative requirements

- Non introdurre `GetSecret` diretto o indiretto.
- Non copiare password grant, bearer fissi, token su disco o certificate-validation bypass del legacy.
- Non fidarsi di tenant, endpoint, secret reference, certificate reference o regione inviati dal client.
- Non registrare header, token, cookie, payload clinici, PIN o stack trace.
- Ogni nuova primitiva richiede test positivi e negativi, scoping, expiry, replay e audit metadata-only.
