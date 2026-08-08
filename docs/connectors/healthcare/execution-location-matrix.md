# Healthcare execution-location matrix

## Rules applied

Execution location is evaluated across five independent dimensions:

1. user interaction location;
2. secret/certificate custody;
3. token/session exchange location;
4. healthcare API execution location;
5. mandatory local capability or hardware.

The resulting classes are:

- `GATEWAY`: credentials/capabilities and the healthcare API call can be managed at Gateway. Browser, direct-application or other user interaction does not by itself require Broker;
- `BROKER/LOCAL`: authentication or the API call necessarily uses installation-local hardware, a non-exportable local key, a local-only API, or an installation-only network/VPN;
- `HYBRID`: a mandatory local capability and a Gateway capability are both required by the same flow;
- `UNKNOWN`: the available evidence cannot establish a required custody, network or capability location.

`GATEWAY, conditional` means the evidence shows no mandatory local capability, but production use still depends on approval or confirmation of central/provider-side key or certificate custody. The client cannot choose or override execution location, endpoint, credential, certificate or signing key.

## Primary matrix

| ID | Service | User interaction | Secret/certificate custody | Token/session exchange | Healthcare API execution | Mandatory local capability/hardware | Location |
|---|---|---|---|---|---|---|---|
| HC-01 | SOGEI human prescriptions | Out-of-band/direct MFA; acquisition mechanism **NEEDS CHARACTERIZATION** | Gateway Basic credential | Gateway session custody/application; completion mechanism **NEEDS CHARACTERIZATION** | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-02 | SOGEI veterinary alternative | None stated | Gateway Basic credential | No session stated | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-03 | Lombardia prescriptions | Local/direct browser | Gateway vendor credential | Gateway authorization/token exchange where permitted; helper/callback topology **NEEDS CHARACTERIZATION** | Gateway SOAP/API | None demonstrated | **GATEWAY** |
| HC-04 | Lombardia FSE | Local/direct browser | Gateway vendor credential | As HC-03, with distinct scope/token session | Gateway REST | None demonstrated | **GATEWAY** |
| HC-05 | Veneto prescriptions | Direct/out-of-band OTP | Certificate/key custody **UNKNOWN** | Gateway-capable SAML/session exchange, exact topology **UNKNOWN** | Gateway-capable SOAP | Whether any key is local-only is **UNKNOWN** | **UNKNOWN** |
| HC-06 | Veneto FSE | As HC-05 | As HC-05 | As HC-05 | Gateway-capable SOAP | As HC-05 | **UNKNOWN** |
| HC-07 | Emilia-Romagna prescriptions | Direct browser/identity portal | Gateway Basic credential | Gateway session custody/application; portal completion **NEEDS CHARACTERIZATION** | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-08 | Emilia-Romagna FSE | None stated | Gateway Basic/PIN secret | No separate exchange stated | Gateway REST | None demonstrated | **GATEWAY** |
| HC-09 | Bolzano prescriptions | None stated | Gateway client credential and mTLS certificate if central custody is approved | Gateway OAuth exchange | Gateway SOAP | None demonstrated | **GATEWAY, conditional** |
| HC-10 | Bolzano FSE | Operator identity binding **NEEDS CHARACTERIZATION** | Central certificate/key custody **NEEDS CHARACTERIZATION** | Gateway-capable STS/Attribute Authority exchange | Gateway SOAP | No local hardware demonstrated | **GATEWAY, conditional** |
| HC-11 | Trento prescriptions | Direct/out-of-band email session | Gateway Basic/HMAC secrets | Gateway session custody/application | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-12 | Trento FSE | As HC-11 | As HC-11 | As HC-11 | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-13 | Liguria prescriptions via SOGEI | As selected SOGEI operation | Gateway SOGEI credential | As HC-01/HC-02 | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-14 | Liguria FSE | None stated | Gateway fixed bearer and mTLS certificate, subject to custody approval | No separate exchange stated | Gateway API | None demonstrated | **GATEWAY, conditional** |
| HC-15 | Piemonte prescriptions via SOGEI | As selected SOGEI operation | Gateway SOGEI credential | As HC-01/HC-02 | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-16 | Piemonte FSE | Direct email/app approval | Gateway Basic/PIN and encryption capability | Gateway session custody/application; approval flow **NEEDS CHARACTERIZATION** | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-17 | Umbria prescriptions via SOGEI | As selected SOGEI operation | Gateway SOGEI credential | As HC-01/HC-02 | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-18 | Umbria FSE | None stated | Gateway only if both pharmacy keys/certificates may be held and used centrally/provider-side | JWT preparation occurs before the call; lifecycle **NEEDS CHARACTERIZATION** | Gateway REST/mTLS | None demonstrated; local non-exportable key would change the design | **GATEWAY, conditional** |
| HC-19 | FVG prescriptions via SOGEI | As selected SOGEI operation | Gateway SOGEI credential | As HC-01/HC-02 | Gateway SOAP | None demonstrated | **GATEWAY** |
| HC-20 | FVG FSE | Local/direct browser | Gateway token custody and signing key only if central/provider-side custody is available | Gateway authorization-code/token exchange | Gateway REST | None demonstrated; local non-exportable signing key would require Hybrid | **GATEWAY, conditional** |
| HC-21 | Puglia prescriptions and FSE | Local smart-card interaction | Personal key remains on local smart card/USB token | Local signing/session; exact split **NEEDS CHARACTERIZATION** | Installation VPN/local call | Smart card/USB token and installation-only VPN | **BROKER/LOCAL** |
| HC-22 | Direct VetInfo veterinary prescriptions | Local/direct browser | Gateway client credential and token custody | Gateway authorization-code/token exchange | Gateway REST | None demonstrated | **GATEWAY** |

## Enforcement implications

- A `GATEWAY` connector accepts domain input and, where required, an opaque user-interaction reference only. It never accepts URI, tenant, scope, client ID, secret reference, certificate reference, issuer, audience or signing profile from the caller.
- User interaction may be presented by a direct application, browser, Broker or another trusted UX adapter; that UX choice does not change connector execution location unless a mandatory local capability is proven.
- A `BROKER/LOCAL` connector exposes a narrow operation bound to an allowed local resource; it is not a general proxy, signing oracle or VPN tunnel.
- A `HYBRID` connector requires evidence of both a mandatory local capability and a Gateway capability; an interactive flow alone is insufficient.
- If mandatory certificate/key custody or installation-only routing cannot be established, publication fails closed and the location remains conditional or `UNKNOWN` as recorded above.
