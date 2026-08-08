# CGM local capability map

## Conclusione

Tra le 38 seam healthcare, **una sola richiede con evidenza forte un Broker locale**: W-07 Puglia SIST, per VPN e smartcard/PIN con firma locale. Una seconda capability locale è reale ma fuori dalle 38 seam pubbliche: drCLOUD Desktop deve accedere a database EMR locali per il sync CGM.

Store certificati, browser callback, email/session entry e lettori tessera non rendono da soli il Broker obbligatorio. Possono essere user interaction o una custodia legacy trasferibile al Gateway.

## Matrice per seam/famiglia

| Seam/famiglia | Evidenza locale | User interaction | Classificazione | Target | Provenance |
|---|---|---|---|---|---|
| W-01 Sistema TS ricetta | Inserimento/rinnovo sessione MFA; local service legacy | Sì | `GATEWAY` | Challenge opaca Gateway | `LEGACY_CODE_WINGESFAR`, `OFFICIAL_CURRENT` |
| W-02/W-09 Lombardia | Browser OAuth helper/callback | Sì | `GATEWAY` o `HYBRID` UI callback, non Broker | Redirect/callback controllato | `LEGACY_CODE_WINGESFAR` |
| W-03 Veneto | Store certificato Windows e OTP | Sì | `GATEWAY` se key esportabile; `HYBRID` altrimenti | Provider centralizzato o local key operation | `LEGACY_CONFIG` |
| W-04 Emilia-Romagna | Sessione ottenuta via SPID/CIE/CNS/portale | Sì | `GATEWAY` | Opaque session challenge | `LEGACY_CODE_WINGESFAR` |
| W-05/W-10 Bolzano | Certificato client/store e SAML | Talvolta | `GATEWAY` o `HYBRID` condizionale | Cert/key provider | `LEGACY_CONFIG` |
| W-07 Puglia | VPN, smartcard/token USB, PIN, firma XML/PKCS#7 | Sì | `BROKER_LOCAL` obbligatorio | Broker con device allowlist e key operation | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-11 FVG / D-05 Liguria | Browser/app callback PKCE | Sì | `GATEWAY` con callback client | PKCE/challenge state nel Gateway | `LEGACY_CODE_WINGESFAR`, `LEGACY_CODE_DRCLOUD` |
| W-12..W-14 e D-08 | Store/app certificate e profili JWT/SAML | No o challenge profile-specific | `GATEWAY`; `HYBRID` solo se key non esportabile | Key/cert provider | `LEGACY_CONFIG`, `LEGACY_CODE_DRCLOUD` |
| W-15 VetInfo | Token legacy in memoria/disco; nessun hardware necessario | Possibile nel target auth | `GATEWAY` | OAuth moderno + cache effimera | `LEGACY_CODE_WINGESFAR` |
| W-17 730 | Basic oppure certificato CNS dallo store CurrentUser | Solo per alternativa CNS | `GATEWAY`; `HYBRID` opzionale | Preferire credential/cert provider accreditato | `LEGACY_CODE_WINGESFAR` |
| W-19 DPC | Nessun hardware; token applicativo | No | `GATEWAY` | Token runtime | `LEGACY_CODE_WINGESFAR` |
| W-20/W-21 WebCare | File di scambio e funzione PC/SC `LeggiTessera` | Sì per acquisizione tessera | `GATEWAY`; lettore come input helper | Il gestionale passa il dato ammesso; Broker solo se auth card provata | `LEGACY_CODE_WINGESFAR` |
| W-22 NSO Enerj | File XML locale | No | `GATEWAY` | Upload strutturato; nessun filesystem server selezionabile dal client | `LEGACY_CODE_WINGESFAR` |
| drCLOUD mobile | Cert/app resource, callback e secure app storage | Sì per OAuth/MFA | `DIRECT` verso SIP Gateway | Nessun desktop bridge richiesto | `LEGACY_CODE_DRCLOUD` |
| drCLOUD Desktop sync | Loopback service e accesso DB EMR | No | `DRCLOUD_LOCAL_BRIDGE` | Resta CGM o diventa adapter locale separato | `LEGACY_CODE_DRCLOUD`, `REVERSE_ENGINEERING_REPORT` |

## MUST_REMAIN_LOCAL

1. Operazioni con smartcard/PIN e VPN locale di W-07, finché il profilo Puglia corrente le impone.
2. Accesso ai database EMR locali del desktop drCLOUD, finché non esiste un'API supportata del gestionale.
3. Operazione privata su certificati realmente non esportabili. Non è provato che tutti i certificati legacy lo siano.

## MAY_MOVE_TO_GATEWAY

- Certificati oggi in PFX, risorsa app o Windows certificate store, previa verifica di ownership e vincoli di accreditamento.
- Browser/app callback OAuth: la UI avvia l'interazione, il Gateway conserva verifier/state/token.
- Session ID inserita manualmente o ricevuta via email/portale: deve diventare challenge/riferimento opaco.
- File queue e payload XML legacy: possono diventare request strutturate o blob con limiti e checksum.
- Lettura tessera usata solo per popolare dati: può restare nel gestionale senza un Broker SIP.

## SHOULD_MOVE_TO_GATEWAY

- Credential catalog e client secret.
- Token/access/refresh cache.
- Routing di endpoint e selezione profilo.
- mTLS, JWT RS256, HMAC e firma quando la key è esportabile/centralizzabile.
- Stato tecnico di workflow, correlation, reconciliation e idempotency.
- FSE2, SAC/SAR, VetInfo, DPC, WebCare e vaccination transport/mapping.

## Contratto minimo del Broker

Il Broker non deve diventare un proxy generico o un secret oracle. Per W-07 è sufficiente un contratto ristretto:

1. dispositivo/certificato selezionato da binding server-owned;
2. challenge all'operatore per PIN senza inviare il PIN al Gateway;
3. firma di digest/XML allowlisted o handshake mTLS locale;
4. egress solo verso destinazioni pubblicate;
5. risposta con risultato firmato, metadata tecnici e nessun secret;
6. replay protection, timeout, cancellazione e audit metadata-only.

Qualsiasi generalizzazione oltre questi casi è `NEEDS_CHARACTERIZATION`.
