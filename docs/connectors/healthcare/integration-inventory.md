# M6 healthcare integration inventory

## Scope and evidence labels

This inventory characterizes the healthcare and public-service integrations identifiable in the supplied repository corpus. It is not evidence of live interoperability and does not authorize production implementation.

- **KNOWN**: explicitly stated by an authorized supplied source. It has not necessarily been verified against a live service or current official specification.
- **INFERRED**: an architectural conclusion drawn from one or more known facts.
- **UNKNOWN**: not present in the available sources.
- **NEEDS CHARACTERIZATION**: required before an implementation or conformance claim can be made.

The primary protocol source is the 22-page supplied document `Autenticazione Servizi Pubblici.pdf`. The sanitized legacy reports and their consolidated HTML are behavioral specifications only. No healthcare implementation source was copied into this work.

## Sources analyzed

| Source class | Material analyzed | Result |
|---|---|---|
| Provided protocol documentation | `input-docs/Autenticazione Servizi Pubblici.pdf`, all 22 pages, visually rendered and text-extracted | **KNOWN** protocol summaries for the national and regional services below; no live verification |
| Sanitized legacy characterization | `input-docs/architettura_sicurezza_gestionali_sanitari.html` and the four Markdown reports in `input-docs` | **KNOWN** integration names, legacy behavior and recurring security failure classes; deliberately excludes operational values |
| Repository architecture | ADR-0007, ADR-0009, ADR-0010, ADR-0011, ADR-0015, ADR-0018 and ADR-0019; implementation plan, test strategy, threat model and migration guidance | **KNOWN** product boundaries and security invariants |
| Existing connector material | Connector Definition v1 documentation and the synthetic Secure Layer and Managed SOAP examples | **KNOWN** server-owned binding and synthetic test conventions; examples are pre-M4 analysis artefacts, not executable real connectors |
| Samples, fixtures and tools | Repository samples, test fixtures, M3 legacy simulator and diagrams | No real healthcare implementation or reusable proprietary code was found; only synthetic product behavior and architectural seams |

The corpus does not contain authoritative WSDL/OpenAPI packages, XML schemas, current service manuals, certificate onboarding policies, conformance suites, sanitized packet captures, or live test credentials for the listed services.

## Primary service inventory

### Identity, transport and authentication

| ID | Service / authority | Protocol and media | Authentication and authorization | Certificates, signing and local dependencies |
|---|---|---|---|---|
| HC-01 | National SOGEI human prescriptions, for regions using the central service | **KNOWN** SOAP + XML; **UNKNOWN** SOAP version, exact content type and namespaces | **KNOWN** HTTP Basic with pharmacy username/password plus an emailed `ID-SESSIONE`; the session is sent in `Authorization2F`. **UNKNOWN** operation-level authorization | **KNOWN** no client certificate; **KNOWN** out-of-band email MFA; no JWT, OAuth, HMAC, SAML or WS-Security stated |
| HC-02 | SOGEI veterinary prescriptions through the central alternative | **KNOWN** SOAP + XML; **UNKNOWN** SOAP version, content type and namespaces | **KNOWN** HTTP Basic with pharmacy username/password; no second factor stated. **UNKNOWN** operation authorization | **KNOWN** no client certificate or signing stated |
| HC-03 | Lombardia regional prescriptions | **KNOWN** SOAP + XML compatible with the national prescription specification | **KNOWN** OAuth 2 authorization-code flow through a desktop helper and regional browser authentication; shared software-house `ClientId`/`ClientSecret`; bearer access token | **KNOWN** user authentication may use remote signature/OTP, SISS/CNS, SPID or CIE; no outbound mTLS stated |
| HC-04 | Lombardia FSE | **KNOWN** REST + JSON | **KNOWN** same OAuth flow as HC-03 with an FSE-specific token/scope; bearer access token | Same browser/user-auth dependency as HC-03; no client certificate stated |
| HC-05 | Veneto regional prescriptions | **KNOWN** SOAP + XML compatible with the national prescription specification | **KNOWN** mTLS plus SAML 2.0 assertion carried in WS-Security; operator OTP is added to the assertion | **KNOWN** shared software-house mTLS certificate and ULSS IAP encryption certificates; password encryption and SAML/WS-Security; emailed OTP |
| HC-06 | Veneto FSE | **KNOWN** same service and flow as HC-05 | **KNOWN** same mTLS + SAML 2.0 + WS-Security flow as HC-05 | Same certificate and OTP dependencies as HC-05 |
| HC-07 | Emilia-Romagna regional prescriptions | **KNOWN** SOAP + XML compatible with the national prescription specification | **KNOWN** HTTP Basic plus `ID-SESSIONE` in `Authorization2F`; operator obtains the session through a regional SPID/CIE/CNS portal | **KNOWN** local browser/identity interaction; no client certificate stated |
| HC-08 | Emilia-Romagna FSE | **KNOWN** REST + JSON; **UNKNOWN** exact media type | **KNOWN** HTTP Basic plus a pharmacy PIN in a header; **UNKNOWN** header name and operation authorization | No client certificate or signing stated |
| HC-09 | Bolzano regional prescriptions | **KNOWN** SOAP + XML compatible with the national prescription specification | **KNOWN** OAuth 2 client credentials, bearer token, an operator tax-code header, and mTLS | **KNOWN** shared authentication certificate plus pharmacy-specific mTLS certificate; no JWT or SAML stated for this service |
| HC-10 | Bolzano FSE | **KNOWN** SOAP + XML final service, SOAP STS and REST Attribute Authority | **KNOWN** two SAML assertions (identity and attributes) plus mTLS | **KNOWN** pharmacy-specific mTLS certificate; username/password at STS; SAML identity and attribute assertions |
| HC-11 | Trento regional prescriptions | **KNOWN** SOAP + XML compatible with the national prescription specification | **KNOWN** fixed HTTP Basic, HMAC-SHA256, and emailed session token sent as `Authorization2F` | **KNOWN** shared HMAC passphrase and pharmacy password participate in MAC input; no client certificate; out-of-band email MFA |
| HC-12 | Trento FSE | **KNOWN** same service and flow as HC-11 | **KNOWN** same Basic + HMAC-SHA256 + session flow | Same MAC and email-MFA dependencies as HC-11 |
| HC-13 | Liguria prescriptions | **KNOWN** delegated to the SOGEI central service | See HC-01 and HC-02 as applicable | See the selected SOGEI service |
| HC-14 | Liguria FSE | **KNOWN** REST + JSON | **KNOWN** fixed software-house bearer token plus mTLS | **KNOWN** common software-house client certificate; assisted-person identifier encryption with a regional public key is stated, but the scheme is **NEEDS CHARACTERIZATION** |
| HC-15 | Piemonte prescriptions | **KNOWN** delegated to the SOGEI central service | See HC-01 and HC-02 as applicable | See the selected SOGEI service |
| HC-16 | Piemonte FSE | **KNOWN** SOAP + XML | **KNOWN** HTTP Basic plus `Authorization2F` session; pharmacy-specific username/password/PIN | **KNOWN** RSA encryption of the FSE PIN; **KNOWN** possible citizen approval through an app; no client certificate stated |
| HC-17 | Umbria prescriptions | **KNOWN** delegated to the SOGEI central service | See HC-01 and HC-02 as applicable | See the selected SOGEI service |
| HC-18 | Umbria FSE | **KNOWN** REST + JSON | **KNOWN** two locally generated RS256 JWTs: bearer access token and `FSE-JWT-Signature`; mTLS | **KNOWN** two pharmacy-specific certificates, one for mTLS and one for signing; key custody and centralizability are **NEEDS CHARACTERIZATION** |
| HC-19 | Friuli Venezia Giulia prescriptions | **KNOWN** delegated to the SOGEI central service | See HC-01 and HC-02 as applicable | See the selected SOGEI service |
| HC-20 | Friuli Venezia Giulia FSE | **KNOWN** REST + JSON | **KNOWN** OAuth 2 Authorization Code + PKCE; access token, ID token, and a locally generated RS256 JWT in distinct headers | **KNOWN** software-house signing certificate; browser authentication may use remote signature/OTP, SISS/CNS, SPID or CIE; no mTLS stated |
| HC-21 | Puglia prescriptions and FSE | **KNOWN** SOAP + XML | **KNOWN** VPN plus WS-Security with XML-DSig | **KNOWN** personal CNS smart card or USB token and local VPN; private key is hardware/local and must not be exported |
| HC-22 | Direct VetInfo veterinary prescriptions | **KNOWN** REST + JSON | **KNOWN** OAuth 2 Authorization Code + PKCE with software-house client credentials and bearer access token | **KNOWN** browser/portal authentication; no client certificate or signing stated |

### Session, token and endpoint lifecycle

| ID | Session/token lifecycle | Endpoint/environment model | Logout/invalidation | Special headers |
|---|---|---|---|---|
| HC-01 | **KNOWN** emailed session valid 16 hours; renewal trigger and concurrent-session rules **UNKNOWN** | **KNOWN** separate MFA, SSN and non-SSN logical destinations are listed; environment taxonomy **UNKNOWN** | **UNKNOWN** | **KNOWN** `Authorization2F`; Basic is an HTTP authorization concern |
| HC-02 | No token/session stated | **KNOWN** distinct veterinary logical destination; environments **UNKNOWN** | Not applicable or **UNKNOWN** | No special application header stated |
| HC-03 | **KNOWN** access token typically 30 minutes; refresh window up to 72 hours for prescription flow | **KNOWN** helper, authorization and prescription destinations are distinct; environments **UNKNOWN** | **UNKNOWN** revocation/logout | **KNOWN** helper session-password header; bearer token. Exact helper header policy **NEEDS CHARACTERIZATION** |
| HC-04 | **KNOWN** FSE refresh window up to 8 hours | Distinct FSE destination; environments **UNKNOWN** | **UNKNOWN** | Bearer token; exact scope/header set **NEEDS CHARACTERIZATION** |
| HC-05 | **KNOWN** emailed OTP valid 16 hours; SAML assertion lifetime **UNKNOWN** | IAP varies by ULSS; MFA and prescription destinations are distinct; environments **UNKNOWN** | **UNKNOWN** | **KNOWN** WS-Security `Security`; exact policy and namespaces **UNKNOWN** |
| HC-06 | Same as HC-05 | Distinct FSE operation/destination over the same family; environments **UNKNOWN** | **UNKNOWN** | Same as HC-05 |
| HC-07 | Session lifetime **UNKNOWN** | Portal plus SSN/non-SSN service bindings; environments **UNKNOWN** | **UNKNOWN** | **KNOWN** `Authorization2F` |
| HC-08 | No token stated | Distinct REST logical destination; environments **UNKNOWN** | Not applicable or **UNKNOWN** | **KNOWN** PIN is sent as a header; name and format **UNKNOWN** |
| HC-09 | Token lifetime, cache and refresh **UNKNOWN** | Separate token and SSN/non-SSN service bindings; environments **UNKNOWN** | **UNKNOWN** | **KNOWN** bearer token and `CF_USER` |
| HC-10 | SAML assertion lifetimes **UNKNOWN** | STS, Attribute Authority and final SOAP destinations; environments **UNKNOWN** | **UNKNOWN** | Assertion placement and WS-* profile **NEEDS CHARACTERIZATION** |
| HC-11 | Emailed session lifetime **UNKNOWN**; HMAC is recomputed for each operation | Separate session and service destinations; environments **UNKNOWN** | **UNKNOWN** | **KNOWN** `Authorization2F`; HMAC location in request body stated, exact element **UNKNOWN** |
| HC-12 | Same as HC-11 | Distinct FSE operation on same family; environments **UNKNOWN** | **UNKNOWN** | Same as HC-11 |
| HC-13 | See HC-01/HC-02 | Central SOGEI binding selected server-side | See HC-01/HC-02 | See HC-01/HC-02 |
| HC-14 | Fixed bearer token; rotation/expiry **UNKNOWN** | One logical FSE API is listed; environments **UNKNOWN** | **UNKNOWN** | Bearer token; no additional header confirmed |
| HC-15 | See HC-01/HC-02 | Central SOGEI binding selected server-side | See HC-01/HC-02 | See HC-01/HC-02 |
| HC-16 | Reuses emailed prescription session; a second citizen-approval session may be created | One logical FSE SOAP binding; environments **UNKNOWN** | **UNKNOWN** | **KNOWN** `Authorization2F`; encrypted PIN is in the body |
| HC-17 | See HC-01/HC-02 | Central SOGEI binding selected server-side | See HC-01/HC-02 | See HC-01/HC-02 |
| HC-18 | JWT lifetime, clock skew and replay policy **UNKNOWN** | One logical FSE API is listed; environments **UNKNOWN** | No logout stated; certificate revocation behavior **UNKNOWN** | **KNOWN** bearer token and `FSE-JWT-Signature` |
| HC-19 | See HC-01/HC-02 | Central SOGEI binding selected server-side | See HC-01/HC-02 | See HC-01/HC-02 |
| HC-20 | **KNOWN** access and ID tokens are described as valid up to 16 hours; refresh behavior **UNKNOWN** | Authorization, token and resource bindings are distinct; environments **UNKNOWN** | **UNKNOWN** | **KNOWN** bearer access token, `ID-TOKEN`, `JWT-SIGNATURE` |
| HC-21 | VPN/session and smart-card PIN lifecycle **UNKNOWN** | **KNOWN** supplied destination is VPN-only and identified as pre-production; production binding **UNKNOWN** | **UNKNOWN** | WS-Security/XML-DSig placement **NEEDS CHARACTERIZATION** |
| HC-22 | **KNOWN** access token 30 minutes; supplied source says refresh token has no stated expiry | Authorization, token and resource bindings are distinct; environments **UNKNOWN** | Logout/revocation **UNKNOWN**; indefinite refresh claim **NEEDS CHARACTERIZATION** with current official documentation | Bearer access token |

### Error, retry and unresolved behavior

The supplied protocol document does not define an error/fault taxonomy, retry policy, idempotency semantics, timeout, rate limit, response size limit, logout protocol, TLS trust profile, XML namespace set or conformance test for any row. Those items are therefore **UNKNOWN** for HC-01 through HC-22 and are **NEEDS CHARACTERIZATION** before production implementation.

At minimum, each service needs:

- authoritative WSDL/OpenAPI/schema and exact operation/SOAPAction/path inventory;
- test and production environment bindings with trust anchors and onboarding rules;
- authentication failure, expired-session/token, authorization denial and service-fault samples;
- replay, retry, idempotency, timeout, rate-limit and maintenance semantics;
- certificate purpose, custody, chain, renewal, revocation and overlap policy;
- data classification and field-level redaction rules;
- confirmation that every user, pharmacy, operator and patient attribute is derived or validated server-side.

## Additional integrations identified in the sanitized legacy corpus

These integrations are identifiable but not sufficiently specified for the first connector wave.

| Candidate | Evidence and currently known primitive | Readiness |
|---|---|---|
| FSE 2.0 national gateway and other regional FSE variants | **KNOWN** recurring OAuth/PKCE, JWT/client assertion and X.509 patterns across several sanitized reports | **NEEDS CHARACTERIZATION** as separate national and regional profiles; do not create one generic FSE adapter |
| Sistema TS / MEF and 730 healthcare-expense submission | **KNOWN** service names and legacy credential/log findings; protocol and grant **UNKNOWN** | Discovery only |
| DPC / webDPC / WgWebcare / WgDPC | **KNOWN** recurring pharmacy integration names; protocol, authority and service equivalence **UNKNOWN** | Discovery only |
| MIR / OSM-Connector / PhronesisNet clinical network | **KNOWN** local/network XML behavior and weak cross-vendor trust findings | **NEEDS CHARACTERIZATION** for topology, schema, identity, replay and XML security; likely separate from public-service connectors |
| PagoPA | **KNOWN** destination name in an aggregated TLS finding; all connector details **UNKNOWN** | Hold |
| NSO / Enerj | **KNOWN** medicine-ordering integration name and vendor-level identity finding; protocol **UNKNOWN** | Hold |
| INPS/INAIL, SDI and IZS services | **KNOWN** only as named categories or aggregated references; operations and protocols **UNKNOWN** | Hold |
| CGM/partner cloud services | **KNOWN** proprietary integration/component names in the reports | Outside the public healthcare shortlist until ownership and authorization are established |
| EReg, CBox, WASP/WASP2, fiscal printers, POS, readers and robots | **KNOWN** local/device services; some REST/JWT/HMAC behavior is stated | Broker/device-adapter track, not the Gateway healthcare pack |

## Characterization conclusion

Only HC-01, HC-03/HC-04, HC-18 and HC-20 have the combination of protocol clarity, reusable primitives and synthetic testability needed for the first four specifications. Even these remain conditional: implementation writers must not start production code until the unresolved questions called out in each specification have authoritative answers or an explicitly approved behavioral characterization.
