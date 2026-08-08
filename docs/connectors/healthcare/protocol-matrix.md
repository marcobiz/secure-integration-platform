# Healthcare protocol matrix

## Reading the matrix

This matrix preserves historical profile hypotheses for architecture planning. A check mark means a primitive was characterized, not that current official evidence is on file; `I` means **INFERRED** and `?` means **UNKNOWN** or **NEEDS PUBLIC SOURCE**. It does not claim conformance or that two authorities use the same profile, claims, namespace, trust chain or lifecycle.

Abbreviations: `SOGEI-H` = national human prescriptions; `SOGEI-V` = national veterinary alternative; `ER` = Emilia-Romagna; `BZ` = Bolzano; `TN` = Trento; `FVG` = Friuli Venezia Giulia.

## Reuse by service

| Primitive | SOGEI-H | SOGEI-V | Lombardia Rx/FSE | Veneto Rx/FSE | ER Rx/FSE | BZ Rx/FSE | TN Rx/FSE | Liguria FSE | Piemonte FSE | Umbria FSE | FVG FSE | Puglia Rx/FSE | VetInfo |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| HTTP Basic | ✓ | ✓ | token endpoint only |  | ✓ | STS username/password, profile ? | ✓ |  | ✓ |  |  |  | token endpoint profile ? |
| Basic + session reference | ✓ |  | helper session plus OAuth code |  | Rx ✓ |  | ✓ |  | ✓ |  |  |  |  |
| OAuth 2 client credentials |  |  | unverified alternate profile; ? |  |  | Rx ✓ |  |  |  |  |  |  |  |
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

Any regional prescription profile that delegates to the central service should reuse only the applicable public central-service primitive set; delegation and profile equivalence require current official evidence.

## Primitive families

### SOAP Basic and session

Reused by SOGEI-H, Emilia-Romagna prescriptions, Trento prescriptions/FSE and Piemonte FSE, with important profile differences. Only SOGEI-H is selected for the first family implementation because it is the clearest baseline. Session acquisition, header format, lifetime and credential ownership must remain profile-specific.

### OAuth browser and token lifecycle

Reused by Lombardia, FVG and VetInfo. The browser/user-auth mechanisms differ and must not be embedded in a generic OAuth client. The reusable core is limited to state/PKCE material, one-time authorization-code handoff, server-owned token exchange, redacted token cache and bearer injection.

No public official source is currently recorded for an alternate application `client_credentials` layer. It is excluded from the public profile until independently documented; profiles must never be combined or auto-negotiated by assumption.

### mTLS and signing

Characterized across several regional profile candidates. Certificate purpose is not interchangeable: mTLS authentication, JWT signing, XML signing and encryption require separate resource capabilities. Every concrete certificate role remains `NEEDS PUBLIC SOURCE`.

### Deferred primitives

- HMAC-SHA256 is a Trento characterization hypothesis; canonical message, request element and public source are missing.
- SAML/WS-Security is characterized for Veneto and Bolzano, but public assertion profiles, namespaces, canonicalization and trust rules are missing.
- Smart-card XML-DSig and VPN are characterized for Puglia and would force a Broker/local track if confirmed by the current authority.

## Shortlist coverage

| Shortlisted connector | Primary primitive coverage | Reuse created |
|---|---|---|
| `sogei-basic-session` | SOAP/XML, Basic, opaque session reference, transport-neutral user-interaction completion, SOAP fault mapping | Basis for ER/TN/Piemonte session profiles after separate characterization |
| `lombardia-oauth-helper` | Authorization Code helper flow, server-owned client credential, token cache/refresh, bearer | OAuth HTTP writer and transport-neutral authorization completion |
| `fvg-pkce-jwt` | Authorization Code + PKCE, access/ID token, RS256 signing, multi-header injection | PKCE/handoff and signing primitives reusable by VetInfo and other FSE profiles |
| `umbria-mtls-jwt` | mTLS plus two RS256 JWT profiles with distinct certificate purposes | Certificate-purpose separation, signing policy and mTLS transport |

The matrix intentionally does not include a universal authentication abstraction. The minimum contracts for these four connectors are defined in [auth-primitives-required.md](auth-primitives-required.md).
