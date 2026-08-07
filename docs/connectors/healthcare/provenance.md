# Healthcare clean-implementation provenance

## Clean-room rule

The supplied legacy and reverse-engineering material is used only as a behavioral specification and test oracle. No proprietary source, decompiled routine, captured credential, certificate, token, private endpoint configuration or raw request/response has been copied into a connector or fixture.

When behavior is known only from observation or a sanitized finding, this characterization records the behavior and creates a synthetic vector. Implementation writers must use authorized official specifications or independently reproduce the behavior against a controlled test service.

## Source register

| Source ID | Source | Classification | SHA-256 / stable reference | Permitted use |
|---|---|---|---|---|
| SRC-PDF | `input-docs/Autenticazione Servizi Pubblici.pdf`, 22 pages, created 2026-06-10 | Provided documentation; not independently verified official documentation | `6A4C9868B666DC1C57042D4BC72CCC300C6587C99AE60DE26BD086AE757E9B96` | Protocol inventory and candidate behavior |
| SRC-HTML | `input-docs/architettura_sicurezza_gestionali_sanitari.html`, 176 finding rows | Sanitized consolidation, restricted source | `E3F1B373B3657939E379DA538FA38F22732179C0F4FD9A6393A16D8B85631EEE` | Integration names, recurring primitive/security patterns and clean boundaries |
| SRC-WGF | `input-docs/CYBERSICUREZZA_WINGESFAR.md` | Sanitized legacy/reverse-engineering report | `E8BB35D9FD4D2CE256B05C53F8F0FC4045C6EF193755DE61972B24B300453ADC` | Behavioral oracle and negative security cases only |
| SRC-DH | `input-docs/REPORT_DEVICEHUB_WINDOWS_v2.md` | Sanitized legacy/reverse-engineering report | `EADCAD564A242640408B6FD3D56E2BCFEB4AF704290538C7D557640558ACE86A` | Local/device boundary and negative security cases only |
| SRC-INF | `input-docs/REPORT_INFANTIA_PROFIM_v2.md` | Sanitized legacy/reverse-engineering report | `FE9C33526E0AE1B155A5103E1E2A4B88719561D82C26FAC05E475F0B8FDA3B79` | Behavioral oracle and negative security cases only |
| SRC-DRC | `input-docs/REPORT_SICUREZZA_CGM_DRCLOUD.md` | Sanitized legacy/reverse-engineering report | `C99DB446E3DAEEFACDCC6145007E6A7358D23F6E055B9877C1FF6133ADA8C34D` | Behavioral oracle and negative security cases only |
| SRC-ADR | ADR-0010, ADR-0011, ADR-0015, ADR-0018 and ADR-0019 | Accepted repository decisions | Repository baseline `8774c252b233456173c3ab31346fb21390fb8d7d` | Connector, execution-location, lifecycle and pack boundaries |
| SRC-CORE | Connector Definition v1, test strategy, sequence diagrams, migration guide and synthetic M3 fixtures/tests | Repository product evidence | Same baseline as SRC-ADR | Existing security invariants and synthetic vector conventions |

Input hashes identify the exact characterized material without adding those restricted/ignored files to Git.

## Evidence taxonomy

| Label | Meaning in this work |
|---|---|
| Official documentation | An authoritative authority/vendor specification actually supplied and reviewed. None of the current protocol sources has been established as this class. |
| Provided documentation | A supplied document that explicitly states behavior. `SRC-PDF` is in this class. |
| Observed legacy behavior | Behavior described by the sanitized product reports or represented by repository test oracles. |
| Reverse-engineering characterization | A static/dynamic finding summarized without code or operational values. |
| Inference | A product design conclusion, such as Gateway/Hybrid location, derived from known facts and ADRs. |
| Unknown | Not present or contradicted in the available sources. |

`KNOWN` elsewhere in this directory means known from one of these sources, not live-verified or officially certified.

## Important fact register

### `sogei-basic-session`

| Fact | Provenance | Status |
|---|---|---|
| SOAP + XML, HTTP Basic and emailed `ID-SESSIONE` in `Authorization2F` | SRC-PDF §1.2, pages 4-5 | **Provided documentation / KNOWN** |
| Session validity is 16 hours | SRC-PDF page 4 | **Provided documentation / KNOWN** |
| No client certificate is stated | SRC-PDF page 4 | **Provided documentation / KNOWN** |
| Gateway plus typed local-MFA handoff | SRC-ADR (ADR-0015) applied to SRC-PDF | **Inference** |
| SOAP version, WSDL operations, namespaces, fault model and invalidation | Not supplied | **UNKNOWN / NEEDS CHARACTERIZATION** |
| Synthetic SOAP and expiry vectors | Independently authored under `tests/characterization/healthcare/sogei-basic-session` | **Synthetic characterization**, not captured traffic |

### `lombardia-oauth-helper`

| Fact | Provenance | Status |
|---|---|---|
| Desktop helper creates a session, opens regional browser auth, polls a result and returns authorization code/redirect URI | SRC-PDF §2.2, pages 6-7 | **Provided documentation / KNOWN** |
| Token endpoint uses HTTP Basic client authentication and `grant_type=authorization_code` | SRC-PDF page 6 | **Provided documentation / KNOWN** |
| Access token is typically 30 minutes; refresh windows differ: prescription up to 72 hours, FSE up to 8 hours | SRC-PDF pages 6-7 | **Provided documentation / KNOWN** |
| Sanitized legacy evidence also identifies a separate application `client_credentials` layer and CRS session | SRC-WGF / SRC-HTML findings summarized in the corpus review | **Observed legacy behavior; apparent profile conflict** |
| PKCE, redirect ownership, helper trust, refresh rotation and logout | Not established | **UNKNOWN / NEEDS CHARACTERIZATION** |
| Browser local, code exchange/token cache/API central | SRC-ADR applied to provided behavior | **Inference** |

The apparent authorization-code versus application-client-credentials difference must be resolved as separate profiles. Writers must not select one by assumption or combine them into a permissive flow.

### `fvg-pkce-jwt`

| Fact | Provenance | Status |
|---|---|---|
| OAuth 2 Authorization Code + PKCE, access token, ID token and signed RS256 JWT | SRC-PDF §9.3, pages 19-20 | **Provided documentation / KNOWN** |
| Headers include bearer authorization, `ID-TOKEN` and `JWT-SIGNATURE` | SRC-PDF page 19 | **Provided documentation / KNOWN** |
| Access and ID token validity is described as 16 hours | SRC-PDF page 19 | **Provided documentation / KNOWN** |
| Client ID and signing certificate are software-house resources | SRC-PDF page 19 | **Provided documentation / KNOWN** |
| PKCE method, state/callback rules, claims, JWT lifetime, key custody, refresh and logout | Not supplied | **UNKNOWN / NEEDS CHARACTERIZATION** |
| Browser/code handoff local, token and signing operations central | SRC-ADR applied to provided behavior | **Inference** |

### `umbria-mtls-jwt`

| Fact | Provenance | Status |
|---|---|---|
| REST + JSON GET protected by mTLS and two RS256 JWTs | SRC-PDF §8.3, page 18 | **Provided documentation / KNOWN** |
| One JWT is bearer `Access Token`; the other is sent in `FSE-JWT-Signature` | SRC-PDF page 18 | **Provided documentation / KNOWN** |
| Separate pharmacy certificates are used for mTLS and signing | SRC-PDF page 18 | **Provided documentation / KNOWN** |
| Sanitized FSE evidence confirms recurring separation of authentication/signing certificate roles | SRC-HTML, SRC-DRC, SRC-INF and SRC-CORE corpus review | **Observed legacy behavior** |
| Exact national-versus-regional profile, claims, body digest, `x5c`, audience, clock skew and renewal | Not supplied | **UNKNOWN / NEEDS CHARACTERIZATION** |
| Gateway execution | SRC-ADR applied conditionally to centrally usable certificates | **Inference; conditional** |

This connector is an Umbria profile. It must not be represented as the national FSE 2.0/ModI profile without separate authoritative characterization.

## Document anomalies retained as gaps

- Cross-references rendered as “see page 4” do not resolve the referenced field definitions.
- Liguria appears under Trento numbering/footer in the supplied PDF.
- Bolzano descriptions appear to mention both a common and pharmacy-specific certificate without a complete role mapping.
- Trento does not define an implementable HMAC canonicalization, encoding or key/message split.
- The direct VetInfo row appears to reuse an FVG authorization host while using IZS token/resource hosts; this may be a copy error and is not reusable as a binding.
- Puglia lists only a VPN-only pre-production destination.
- “100% compatible with SOGEI” is a statement in the supplied document, not conformance evidence.

## Information that may not cross into implementation

- source code, decompiled expressions or proprietary identifiers not necessary to the public contract;
- real hosts copied into Connector definitions rather than environment bindings;
- real email addresses, identities, pharmacy codes, patient data or operator data;
- credentials, passphrases, tokens, PINs, PFX/certificate bytes, private keys or captured authorization artefacts;
- a client-controlled tenant, installation, pharmacy, operator, endpoint, scope, audience, header, secret reference or certificate reference;
- legacy trust-all TLS, fixed shared identities, generic proxy/signing operations, direct egress bypasses or sensitive logging behavior.

## Writer handoff rule

The authentication writers may implement only the minimal synthetic contracts in [auth-primitives-required.md](auth-primitives-required.md). A connector writer may start a production profile only after every mandatory unresolved field in its specification is backed by official documentation or an approved independent characterization vector, with provenance added here.
