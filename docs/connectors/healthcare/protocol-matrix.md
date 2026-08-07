# Healthcare protocol matrix

## Reading the matrix

This matrix groups only behavior supported by the supplied sources. A check mark means the primitive is explicitly described (**KNOWN**); `I` means **INFERRED** from the named protocol; `?` means **UNKNOWN** or **NEEDS CHARACTERIZATION**. It does not claim that two authorities use the same profile, claims, namespace, trust chain or lifecycle.

Abbreviations: `SOGEI-H` = national human prescriptions; `SOGEI-V` = national veterinary alternative; `ER` = Emilia-Romagna; `BZ` = Bolzano; `TN` = Trento; `FVG` = Friuli Venezia Giulia.

## Reuse by service

| Primitive | SOGEI-H | SOGEI-V | Lombardia Rx/FSE | Veneto Rx/FSE | ER Rx/FSE | BZ Rx/FSE | TN Rx/FSE | Liguria FSE | Piemonte FSE | Umbria FSE | FVG FSE | Puglia Rx/FSE | VetInfo |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| HTTP Basic | ✓ | ✓ | token endpoint only |  | ✓ | STS username/password, profile ? | ✓ |  | ✓ |  |  |  | token endpoint profile ? |
| Basic + session reference | ✓ |  | helper session plus OAuth code |  | Rx ✓ |  | ✓ |  | ✓ |  |  |  |  |
| OAuth 2 client credentials |  |  | conflicting legacy evidence; ? |  |  | Rx ✓ |  |  |  |  |  |  |  |
| Authorization Code |  |  | ✓ |  |  |  |  |  |  |  | ✓ |  | ✓ |
| PKCE |  |  | not stated; ? |  |  |  |  |  |  |  | ✓ |  | ✓ |
| Bearer token |  |  | ✓ |  |  | Rx ✓ |  | ✓ fixed |  | ✓ JWT | ✓ access token |  | ✓ |
| JWT RS256 |  |  |  |  |  |  |  |  |  | two JWTs ✓ | one signed JWT ✓ |  |  |
| mTLS |  |  |  | ✓ |  | ✓ |  | ✓ |  | ✓ |  |  |  |
| Certificate signing |  |  |  | password encryption / SAML, profile ? |  | SAML profile ? |  | identifier encryption only | RSA PIN encryption only | ✓ | ✓ | XML-DSig via hardware |  |
| HMAC-SHA256 |  |  |  |  |  |  | ✓ |  |  |  |  |  |  |
| SOAP | ✓ | ✓ | Rx ✓ | ✓ | Rx ✓ | Rx/FSE ✓ | ✓ |  | ✓ |  |  | ✓ |  |
| XML | ✓ | ✓ | Rx ✓ | ✓ | Rx ✓ | Rx/FSE ✓ | ✓ |  | ✓ |  |  | ✓ |  |
| SAML |  |  |  | ✓ |  | FSE ✓ |  |  |  |  |  |  |  |
| WS-Security |  |  |  | ✓ |  | FSE profile ? |  |  |  |  |  | ✓ |  |
| OTP / second factor | email session ✓ |  | browser identity ✓ | email OTP ✓ | portal identity ✓ | certificate/user context | email session ✓ |  | email + citizen app | certificate possession | browser identity ✓ | smart card | portal identity ✓ |
| Smart card / local certificate |  |  | possible SISS/CNS |  | possible CNS at portal |  |  |  |  |  | possible SISS/CNS at portal | ✓ |  |
| VPN / local-only dependency |  |  |  |  |  |  |  |  |  |  |  | ✓ |  |

Regional prescription rows that delegate to SOGEI (Liguria, Piemonte, Umbria and FVG in the supplied document) reuse the applicable SOGEI primitive set and are not separate protocol implementations.

## Primitive families

### SOAP Basic and session

Reused by SOGEI-H, Emilia-Romagna prescriptions, Trento prescriptions/FSE and Piemonte FSE, with important profile differences. Only SOGEI-H is selected for the first family implementation because it is the clearest baseline. Session acquisition, header format, lifetime and credential ownership must remain profile-specific.

### OAuth browser and token lifecycle

Reused by Lombardia, FVG and VetInfo. The browser/user-auth mechanisms differ and must not be embedded in a generic OAuth client. The reusable core is limited to state/PKCE material, one-time authorization-code handoff, server-owned token exchange, redacted token cache and bearer injection.

The Lombardia sources conflict: the supplied protocol matrix describes Authorization Code through a desktop helper, while sanitized legacy evidence also identifies a separate application `client_credentials` token layer and CRS session. This is **NEEDS CHARACTERIZATION**, not a reason to merge both flows.

### mTLS and signing

Reused by Veneto, Bolzano, Liguria, Umbria and other sanitized FSE evidence. Certificate purpose is not interchangeable: mTLS authentication, JWT signing, XML signing and encryption require separate resource capabilities. Umbria is selected because the supplied document explicitly distinguishes two pharmacy certificates and two JWT profiles.

### Deferred primitives

- HMAC-SHA256 is confirmed for Trento, but its exact canonical message and request element are missing.
- SAML/WS-Security is confirmed for Veneto and Bolzano, but assertion profiles, namespaces, canonicalization and trust rules are missing.
- Smart-card XML-DSig and VPN are confirmed for Puglia and force a Broker/local track.
- Fixed bearer tokens, HS256 JWT, OAuth 1, WebSocket and device protocols appear in the sanitized legacy corpus but are not needed by the four shortlisted connectors.

## Shortlist coverage

| Shortlisted connector | Primary primitive coverage | Reuse created |
|---|---|---|
| `sogei-basic-session` | SOAP/XML, Basic, opaque session reference, transport-neutral user-interaction completion, SOAP fault mapping | Basis for ER/TN/Piemonte session profiles after separate characterization |
| `lombardia-oauth-helper` | Authorization Code helper flow, server-owned client credential, token cache/refresh, bearer | OAuth HTTP writer and transport-neutral authorization completion |
| `fvg-pkce-jwt` | Authorization Code + PKCE, access/ID token, RS256 signing, multi-header injection | PKCE/handoff and signing primitives reusable by VetInfo and other FSE profiles |
| `umbria-mtls-jwt` | mTLS plus two RS256 JWT profiles with distinct certificate purposes | Certificate-purpose separation, signing policy and mTLS transport |

The matrix intentionally does not include a universal authentication abstraction. The minimum contracts for these four connectors are defined in [auth-primitives-required.md](auth-primitives-required.md).
