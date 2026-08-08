# CGM target architecture

## Target

```mermaid
flowchart TB
    subgraph Local["Farmacia / postazione locale"]
        W["Wingesfar"]
        D["drCLOUD+"]
        B["SIP Broker — solo smartcard/VPN/non-exportable key"]
        E["drCLOUD Desktop EMR sync — fuori dal path sanitario"]
        DB["EMR database locale"]
        E --> DB
    end

    subgraph SIP["Secure Integration Platform"]
        G["SIP Gateway"]
        R["Published connector definitions + server-owned bindings"]
        P["Secret / Certificate / Key Operation providers"]
        O["Opaque auth, token, workflow and audit state"]
        R --> G
        P --> G
        O --> G
    end

    W -->|"Direct"| G
    D -->|"Direct"| G
    W -->|"Puglia/local key only"| B
    B -->|"Broker execution"| G
    E --> CGM["CGM cloud product services"]

    G --> F2["FSE2 National"]
    G --> TS["Sistema TS prescription / expenses / other"]
    G --> V["VetInfo"]
    G --> REP["Regional ePrescription profiles"]
    G --> RFC["Regional FSE consumer profiles"]
    G --> DPC["DPC"]
    G --> WC["WebCare / assistance"]
    G --> VX["Vaccination"]
    G --> OT["Other accredited services"]
```

## Execution mode

| Scenario | Mode | Ragione |
|---|---|---|
| Credenziali/certificati centralizzabili, OAuth, Basic, JWT, mTLS | `GATEWAY` | Custodia e routing server-side; nessun requisito hardware locale |
| Smartcard/PIN e VPN Puglia | `BROKER_LOCAL` | Device e rete sono realmente locali |
| Browser/app callback | `DIRECT` verso Gateway con user interaction | Il callback non richiede un proxy locale generico |
| Certificato non esportabile | `HYBRID` | Gateway orchestra, Broker esegue key operation |
| drCLOUD Desktop EMR sync | Fuori SIP healthcare | Data extraction/product sync, non connector pubblico |

## Trasferimento delle responsabilità

| Oggi | Target | Effetto |
|---|---|---|
| Endpoint e profilo in config/app | Definizione pubblicata e binding server-owned | Il client non sceglie la destinazione |
| Password/client secret locali | `ISecretProvider` | Riduzione secret distribuiti |
| PFX/store/app certificate | `ICertificateProvider`/`IKeyOperationProvider` | Custodia separata dall'uso |
| Token/sessioni in memoria o disco client | Cache runtime cifrata e opaca Gateway | Expiry e audit centralizzati |
| OAuth helper per prodotto | Auth challenge SIP | PKCE/state/replay uniformi |
| JWT/SAML/HMAC/XML signing nei moduli | Key operations provider-neutral | Niente private key nel connector |
| Factory regionale distribuita | Connector definition + profile | Rollout, checksum e four-eyes publication |
| FSE producer Lombardia/Sardegna | FSE2 national lifecycle | Due seam regionali ritirate |
| FSE consumer regionale | Adapter regionale dedicato | Resta separato da FSE2 |
| drCLOUD CGM trace/cataloghi | CGM cloud | Non contaminano il Core SIP |

## Boundary di sicurezza

- Wingesfar e drCLOUD inviano solo operation input e riferimenti di workflow; tenant/installazione, endpoint, secret e certificate binding derivano da stato autenticato server-side.
- Il Gateway applica grant deny-by-default per connector/operation e restricted egress.
- Provider separati per secret retrieval interno, certificate use, key/signing e MAC; nessuna capability `GetSecret` per client, Broker o Admin UI.
- Il Broker riceve un task firmato e allowlisted, non un URL arbitrario o una reference scelta dal caller.
- Audit solo metadata; payload clinici, token, cookie, authorization header, PIN e stack trace non sono evidenza.
- Publication immutabile, checksum-specific e four-eyes prima del rollout CGM.

## Stato e disponibilità

Il Gateway deve persistere correlation, idempotency e stato tecnico senza duplicare lo stato clinico autorevole. Token e challenge hanno expiry e cache effimera/cifrata. Se una definizione pubblicata o un provider non è disponibile, l'esecuzione fallisce chiusa; non effettua fallback silenzioso a endpoint o credenziali locali.

## Strategia di coesistenza

```mermaid
stateDiagram-v2
    [*] --> Legacy
    Legacy --> ShadowRead: profilo e auth accreditati
    ShadowRead --> CanaryWrite: equivalenza read/fault verificata
    CanaryWrite --> SIPPrimary: reconciliation write stabile
    SIPPrimary --> LegacyFallback: solo incidente dichiarato
    LegacyFallback --> SIPPrimary: correzione + gate completo
    SIPPrimary --> Retired: finestra senza fallback + secret revocati
```

Il fallback è esplicito e temporaneo. Il retirement include revoca/rotazione dei secret legacy, rimozione della route e prova che nessuna factory/config la selezioni più.
