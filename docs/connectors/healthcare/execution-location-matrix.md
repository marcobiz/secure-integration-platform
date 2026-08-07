# Healthcare execution-location matrix

## Rules applied

ADR-0015 is controlling:

- `GATEWAY`: server-owned vendor/tenant credential, centrally usable certificate, token exchange or public-network service call;
- `BROKER/LOCAL`: physical smart card, local-only non-exportable key, installation VPN or local hardware/network;
- `HYBRID`: only a typed authorization-code, local-signature or local-MFA handoff crosses between Broker and Gateway;
- `UNKNOWN`: available evidence cannot establish the required custody or network location.

The client cannot choose or override the execution location, endpoint, credential, certificate or signing key.

## Primary matrix

| ID | Service | Location | Technical rationale and condition |
|---|---|---|---|
| HC-01 | SOGEI human prescriptions | **HYBRID** | Gateway owns Basic credential and external SOAP binding; operator receives the MFA session out of band and Broker performs a typed local-MFA handoff. Raw credential or destination never comes from the client. |
| HC-02 | SOGEI veterinary alternative | **GATEWAY** | Basic credential and SOAP destination can be bound server-side; no local hardware or browser flow is stated. |
| HC-03 | Lombardia prescriptions | **HYBRID** | Browser/portal authentication and authorization code are local; helper/token exchange, client secret, token cache and service call belong at Gateway. Helper callback/polling topology is **NEEDS CHARACTERIZATION**. |
| HC-04 | Lombardia FSE | **HYBRID** | Same authorization-code handoff as HC-03 with a distinct server-owned scope/token session. |
| HC-05 | Veneto prescriptions | **HYBRID** | Central mTLS/SAML is possible, but operator OTP is out of band. The IAP certificate/encryption topology and whether any key is local-only are **NEEDS CHARACTERIZATION**. |
| HC-06 | Veneto FSE | **HYBRID** | Same constraints as HC-05. |
| HC-07 | Emilia-Romagna prescriptions | **HYBRID** | Operator obtains session through SPID/CIE/CNS portal; Gateway can own Basic credential and SOAP call after a typed local-MFA handoff. |
| HC-08 | Emilia-Romagna FSE | **GATEWAY** | Basic credential, PIN header and REST destination can be server-owned; the PIN must be a scoped secret, not client input. |
| HC-09 | Bolzano prescriptions | **GATEWAY** | OAuth client credentials and pharmacy mTLS certificate can be tenant-scoped Gateway resources if onboarding permits central custody. Otherwise location becomes **UNKNOWN** pending certificate policy. |
| HC-10 | Bolzano FSE | **GATEWAY**, conditional | STS, Attribute Authority, SAML and mTLS are network/server operations. Central certificate/key custody and operator identity binding must be confirmed. |
| HC-11 | Trento prescriptions | **HYBRID** | Shared Basic/HMAC material must be server-owned; emailed session is local MFA. Gateway computes HMAC and invokes SOAP after typed handoff. |
| HC-12 | Trento FSE | **HYBRID** | Same constraints as HC-11. |
| HC-13 | Liguria prescriptions via SOGEI | **HYBRID** | Reuses HC-01/HC-02 according to selected national operation. |
| HC-14 | Liguria FSE | **GATEWAY** | Fixed bearer, mTLS certificate and regional public key are server-side resources; no local device is stated. |
| HC-15 | Piemonte prescriptions via SOGEI | **HYBRID** | Reuses HC-01/HC-02 according to selected national operation. |
| HC-16 | Piemonte FSE | **HYBRID** | Emailed session and possible citizen app approval are local/user interactions; Basic credential, PIN encryption and SOAP call can be central. |
| HC-17 | Umbria prescriptions via SOGEI | **HYBRID** | Reuses HC-01/HC-02 according to selected national operation. |
| HC-18 | Umbria FSE | **GATEWAY**, conditional | Two pharmacy-specific certificates support mTLS and signing without stated local hardware. GO requires confirmation that both keys may be held/used by an approved server-side provider. |
| HC-19 | FVG prescriptions via SOGEI | **HYBRID** | Reuses HC-01/HC-02 according to selected national operation. |
| HC-20 | FVG FSE | **HYBRID** | Browser/PKCE and authorization code are local; token exchange, token cache, software-house signing certificate and API call are central. |
| HC-21 | Puglia prescriptions and FSE | **BROKER/LOCAL** | Service is VPN-only and XML-DSig uses a personal smart card/USB token. Neither the network dependency nor private key may be moved to Gateway. A future typed local-signature hybrid requires separate threat analysis if the network call is ever centralized. |
| HC-22 | Direct VetInfo veterinary prescriptions | **HYBRID** | Browser/PKCE is local; client secret, token exchange/cache and REST call belong at Gateway. |

## Sanitized legacy-only candidates

| Candidate | Location | Rationale |
|---|---|---|
| FSE 2.0 national mTLS/JWT family | **GATEWAY**, conditional | Shared reports identify centralizable mTLS and signing resources, but official profiles and key custody are absent. |
| DPC/webDPC, Sistema TS/730, PagoPA, NSO and other named public services | **UNKNOWN** | Protocol and network/custody evidence is insufficient. |
| MIR/OSM/Phronesis network | **UNKNOWN/HYBRID** | Local network behavior is known; topology and identity model are not. |
| EReg, CBox, Gematik, smart-card readers, fiscal printers and robots | **BROKER/LOCAL** | Installation-local hardware or network dependency. |

## Enforcement implications

- A `GATEWAY` connector accepts domain input only. It never accepts URI, tenant, scope, client ID, secret reference, certificate reference, issuer, audience or signing profile from the caller.
- A `BROKER/LOCAL` connector exposes a narrow operation bound to an allowed local resource; it is not a general proxy, signing oracle or VPN tunnel.
- A `HYBRID` connector exchanges only an opaque, one-time typed handoff. Browser codes, MFA artifacts and resulting tokens are not returned as reusable values to the legacy application.
- If certificate custody, VPN routing or browser callback ownership cannot be confirmed, publication fails closed and the location remains `UNKNOWN`.
