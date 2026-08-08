# M6 Healthcare Characterization - implementation plan

## Decision summary

This branch performs characterization only. It does not implement production authentication, connectors, Gateway Core, Broker, shared contracts or a legacy adapter.

The task calls this work “M6 Healthcare Characterization”. The repository roadmap at baseline `8774c252b233456173c3ab31346fb21390fb8d7d` names M6 “Adapter legacy” and healthcare production work M8. This plan preserves the canonical roadmap and treats “M6 Healthcare Characterization” as the authorized workstream/branch label. It does not start either the legacy-adapter milestone or the production healthcare pack milestone.

## Selected connector families

| Priority | Connector | Reuse | Breadth/value | Specification clarity | Synthetic testability | Decision |
|---:|---|---|---|---|---|---|
| 1 | `sistema-ts-eprescription` | National SAC dispenser contracts confirmed; SAR protocol variants excluded | High national prescription coverage | Official WSDL/XSD and MFA current; blocked by missing server-owned HTTP session-header placement | High for SOAP/Basic/session behavior after prerequisite | Wave 1 hard stop |
| 2 | `lombardia-oauth-helper` | High for OAuth token/session patterns | High regional prescription + FSE value | Medium-low: helper and source-profile conflict remain | High for helper/OAuth state machine | Wave 1, conditional |
| 3 | `fvg-pkce-jwt` | High for PKCE/code handoff and RS256 | Strong FSE profile and reusable browser flow | Medium: high-level flow clear, claims/API missing | High for PKCE/token/JWT policy negatives | Wave 2 |
| 4 | `umbria-mtls-jwt` | High for purpose-separated mTLS/signing | Strong FSE/mTLS/JWT coverage | Medium: certificate roles clear, claims/API missing | High with ephemeral certificates/keys | Wave 2, conditional on key custody |

The sequence is a technical characterization order only. It is not customer, market, deployment-volume or commercial prioritization.

### Deferred

- Veneto and Bolzano SAML/WS-Security profiles: assertion, encryption, namespace and trust profiles are incomplete.
- Trento HMAC: canonical message, encoding, timestamp and key roles are ambiguous.
- Puglia: local VPN, smart card/CNS and XML-DSig require a Broker/local track and hardware lab.
- Piemonte: session plus citizen-app approval adds an uncharacterized interactive state machine.
- VetInfo direct remains deferred until current public OAuth metadata, token/resource ownership and refresh policy are confirmed.
- Other healthcare, payment, ordering and device integrations require independent public sources and demand evidence before entering the product roadmap.

## Required work before production implementation

For each selected connector, obtain or independently characterize:

1. current official WSDL/OpenAPI/schema and version;
2. operation inventory, request/response fields and authorization model;
3. test/production environment, TLS trust and onboarding;
4. exact auth profile, lifecycle, logout/revocation and certificate/key custody;
5. fault/error taxonomy, timeout, throttling, retry and idempotency;
6. data classification, minimization, audit and redaction;
7. public conformance samples or independently authored synthetic vectors recorded under the rules in `provenance.md`.

Until then, only synthetic primitive writers are GO.

## Proposed pack boundary

No directories under `src` are created by this characterization. The future physical proposal is:

```text
src/ConnectorPacks/Healthcare/
  Healthcare.ConnectorPack/
    pack manifest and explicit startup registration
  Healthcare.Shared/
    healthcare-only value types, redaction metadata and profile validation
  Sogei.BasicSession/
    compiled SOAP profile and operation mappings
  Lombardia.OAuthHelper/
    compiled helper/OAuth profile and operation mappings
  Fvg.PkceJwt/
    compiled PKCE/JWT profile and operation mappings
  Umbria.MtlsJwt/
    compiled mTLS/dual-JWT profile and operation mappings
  Schemas/
    authorized versioned WSDL/XSD/JSON schemas or generated bounded models
  Tests/
    pack contract, regression, negative-security and synthetic E2E tests
```

### Allowed dependencies

```text
Healthcare Pack
  -> public Gateway Connector Runtime abstractions
  -> public auth-http/auth-soap abstractions
  -> public provider capability abstractions
  -> framework/runtime libraries approved by central package management
```

The pack must not reference Gateway `Domain`, `Application`, `Infrastructure`, composition internals, database types, Azure SDK types, Broker internals, Admin UI, another commercial pack or legacy product assembly. Core must never reference the Healthcare Pack. Architecture tests and the Core export must prove the dependency direction.

Provider access remains capability-specific: secret retrieval, client-certificate use, signing/key use and health/capability discovery are separate. No generic KMS, generic signing oracle, raw HTTP proxy or `GetSecret` surface is allowed.

## Wave 1

### Connector 1 - `sistema-ts-eprescription`

| Area | Plan |
|---|---|
| Primitives | AP-01 server-bound Basic, AP-02 transport-neutral interactive challenge/opaque session, AP-07 secure SOAP/XML boundary, plus a separately authorized server-owned HTTP session-header placement primitive |
| User interaction | Out-of-band ID-session delivery is official; presentation remains transport-neutral and does not require Broker |
| Custody | Basic credential and ID-session remain at Gateway; the SAC profile does not introduce a client certificate |
| Shared work | XML safety limits and opaque session lifecycle exist; HTTP placement is missing |
| Complexity | Official WSDL/XSD mapping is now available; implementation is blocked before generation |
| Risks | Raw/caller header injection, session artifact binding, sensitive XML/fault leakage, accidental generic proxy |
| Official source status | Current SSN dispenser 1.5.1, 2026-04-28 WSDL/XSD kit, MFA 1.1 and 2025-09-02 ID-session kit frozen in the Wave 1 registry |
| Tests | Not started by hard stop; future suite must cover lifecycle, redaction, XML, routing, replay, substitution and business transitions |
| Execution | **GATEWAY** for National/SAC; regional execution remains a server-owned profile reference only |
| Synthetic implementation | Not started because the official authentication profile cannot be expressed by M6 |
| Production blocker | `BLOCKED_BY_GENERIC_PRIMITIVE`: fixed `Authorization2F` HTTP placement; accreditation remains separate |

### Connector 2 - `lombardia-oauth-helper`

| Area | Plan |
|---|---|
| Primitives | AP-03 browser/code handoff, AP-04 OAuth exchange/cache/bearer, AP-01 if HTTP Basic client auth is confirmed |
| User interaction | Local/direct browser; helper/callback/browser coordination **NEEDS CHARACTERIZATION** |
| Custody | Client/vendor credential and token session remain at Gateway; no client certificate is stated |
| Shared work | Opaque authorization attempt, token-session store, single-flight refresh, sanitized OAuth errors |
| Complexity | High because helper trust and conflicting profile evidence must be resolved |
| Risks | Callback/state fixation, helper credential exposure, refresh replay, token vending, mixing FSE/prescription scopes |
| External unknowns | Current helper topology, registered redirect, state/PKCE requirements, grant/client-auth profile, lifecycle, errors, environments and resource contracts |
| Tests | Helper pending/completed/canceled; state mismatch/code replay; token expiry/refresh concurrency; invalid grant; bearer/log redaction |
| Execution | **GATEWAY**: authorization/token exchange and API execution at Gateway where the confirmed flow permits; no mandatory local capability demonstrated |
| Synthetic implementation | Can start after explicit auth-writer milestone authorization |
| Production blocker | Helper ownership/trust, conflicting auth profiles, API contracts, lifecycle, errors and environments are unresolved |

## Wave 2

### Connector 3 - `fvg-pkce-jwt`

| Area | Plan |
|---|---|
| Primitives | AP-03 Authorization Code + S256 PKCE, AP-04 token session, AP-05 policy-bound RS256 signing |
| User interaction | Local/direct browser |
| Custody | Tokens remain at Gateway; signing key must be available through approved central/provider-side custody |
| Shared work | Reuse Wave 1 attempt/token store; introduce signing profiles and replay-safe claim generation |
| Complexity | High |
| Risks | Incorrect identity semantics or authority binding; algorithm confusion; authorization-code leakage; replay |
| External unknowns | OAuth metadata, redirects/scopes/client auth, lifecycle, token validation, JWT claim/header profile, error contracts, environments, key custody and FSE API schema |
| Tests | PKCE positive/mismatch; state/nonce/code reuse; issuer/audience/expiry; wrong algorithm/key purpose; three auth headers; redaction |
| Execution | **GATEWAY, conditional** on central/provider-side signing-key custody; a proven local non-exportable key would require Hybrid redesign |
| Synthetic implementation | Can start after explicit auth-writer/signing milestone authorization using ephemeral per-run material |
| Production blocker | Official OAuth/JWT/API contracts, lifecycle, environments, errors and approved signing-key custody are missing |

### Connector 4 - `umbria-mtls-jwt`

| Area | Plan |
|---|---|
| Primitives | AP-05 two policy-bound RS256 profiles, AP-06 purpose-bound mTLS |
| User interaction | None stated |
| Custody | Separate mTLS and signing keys/certificates must be available through approved central/provider-side custody |
| Shared work | Certificate inventory/versioning, signing provider handle, TLS channel invalidation, replay-safe claims |
| Complexity | High |
| Risks | Treating regional profile as national, certificate-purpose confusion, private-key custody, claim/request mismatch, stale certificate channel |
| External unknowns | Exact dual-JWT lifecycle/reuse/replay profile, national/regional applicability, certificate onboarding/EKU/rotation, environments, request schema and API error policy |
| Tests | Separate auth/sign certs; wrong-purpose denial; expiry/revocation; wrong issuer/audience/alg; mTLS trust/hostname; no key material in evidence |
| Execution | **GATEWAY, conditional** on central/provider-side custody and use of both key/certificate purposes |
| Synthetic implementation | Can start after explicit auth-writer/signing milestone authorization using ephemeral per-run material and **SYNTHETIC TEST POLICY** lifetimes |
| Production blocker | Official JWT/API contracts, lifecycle/replay behavior, environments, errors and approved custody for both keys are missing |

## Parallel development plan

After the public runtime/auth contracts are explicitly authorized and frozen, these workstreams can proceed independently:

| Track | Can start | Produces | Blocks |
|---|---|---|---|
| A - `auth-soap` | After explicit implementation authorization, with synthetic profiles | AP-01/AP-02/AP-07, SOAP mock, XML/fault/redaction tests | SOGEI profile mapping |
| B - `auth-http` | After explicit implementation authorization, with synthetic profiles | AP-03/AP-04, OAuth mock, attempt/token lifecycle tests | Lombardia and FVG profile mapping |
| C - certificate/signing | Implemented locally after explicit authorization; final CI/review pending | AP-05/AP-06, purpose/rotation/replay tests and local synthetic mTLS server | FVG signing and Umbria profile mapping remain blocked on characterization |
| D1 - SOGEI characterization | In parallel with A | Authoritative operation/schema/fault matrix | Production SOGEI connector |
| D2 - Lombardia characterization | In parallel with B | Resolved helper/grant/resource profiles | Production Lombardia connector |
| D3 - FVG characterization | In parallel with B/C | OAuth/JWT/API profile | Production FVG connector |
| D4 - Umbria characterization | In parallel with C | Certificate/JWT/API profile and custody approval | Production Umbria connector |
| E - pack/release boundary | After first compiled profile exists | pack manifest, architecture tests, signing/export policy | Publication of any healthcare pack |

Tracks A, B and C do not depend on each other. D1-D4 do not share restricted source code or raw evidence. Connector profile code waits only for its own authoritative characterization plus the relevant primitive track. Cross-track integration uses public contracts and synthetic vectors.

## Validation strategy

### Characterization gate

- all Markdown links and repository documentation validation;
- every JSON/XML fixture parsed with DTD prohibited;
- PKCE S256 verifier/challenge consistency;
- no compact JWT, private key, PFX/DER/PEM or real certificate bytes in Git;
- no operational authentication artefact, endpoint, identity or raw evidence;
- repository secret scan and `git diff --check`;
- manual provenance review: each fact is official/provided/observed/inferred/unknown.

### Future primitive gate

- positive and negative named tests from `auth-primitives-required.md`;
- resource purpose and cross-tenant/operation denial before provider/DNS/transport;
- token/session/certificate rotation and stale-cache denial;
- XML/JSON bounds, TLS/SSRF/redirect and log/error redaction;
- synthetic provider/mock E2E; no live healthcare claim.

### Future real-connector gate

- authoritative contract checksum/version in provenance;
- conformance against authorized test environment;
- threat model and requirements traceability update;
- published immutable binding/four-eyes approval;
- pack signature/publisher/architecture/Core-export checks;
- separately approved live evidence stored outside Git.

## Decision

- **GO** to start the `auth-soap`, `auth-http` and certificate/signing writers against the small synthetic contracts, once that implementation milestone is explicitly authorized.
- **GO** to continue independent official-document and controlled-test characterization for all four selected profiles.
- **NO-GO** to implement or publish any production healthcare connector today.
- **NO-GO** for SAML/WS-Security, HMAC, smart-card/VPN, legacy adapters or a universal authentication framework in this workstream.
