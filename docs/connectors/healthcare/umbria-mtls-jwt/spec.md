# Umbria mTLS + dual-JWT connector characterization

**Characterization status:** conditional Wave 2 candidate, not implementation-ready.

## Purpose

Provide the regional Umbria FSE pharmacy profile described in the supplied documentation: a fixed REST GET over mTLS using one pharmacy certificate for transport authentication and a separate pharmacy certificate/key for two RS256 JWT profiles.

This specification deliberately does not claim conformance with national FSE 2.0/ModI or any other regional profile.

## Operations

| Operation | Purpose | Status |
|---|---|---|
| `query-fse-prescriptions` | Invoke the fixed regional FSE query with mTLS, bearer JWT and `FSE-JWT-Signature` | High-level method/auth **KNOWN**; request/response/claims **NEEDS CHARACTERIZATION** |

No generic sign, issue-token, invoke-URL or raw REST operation is exposed.

## Allowed inbound parameters

- domain query fields explicitly admitted by the future authoritative operation schema;
- correlation/deadline metadata from authenticated runtime state.

No token/session parameter is expected. The caller cannot supply endpoint, pharmacy/operator identity as authority, certificate/key reference, JWT claims/header, issuer, audience, lifetime, algorithm, bearer/header value, TLS policy or query template.

## Server-owned parameters

The future Connector/Binding must fix resource endpoint, REST method/path/query mapping, two distinct certificate resources, two JWT profiles, claim derivation and all lifecycle/replay settings once characterized, outbound header names, TLS policy, timeout, limits, retry/idempotency, error mapping and redaction.

## Endpoint binding

One logical `fse-resource-api` binding is sufficient for the characterized operation. Environment, base URI, trust anchors, DNS policy and allowed port are server-owned. The supplied URL is evidence only and is not copied into Connector definition or fixtures.

## Required secret and certificate resources

| Resource | Capability | Requirement |
|---|---|---|
| `umbria-mtls-client-certificate` | Client-certificate use | Pharmacy-scoped certificate/key approved for mTLS only |
| `umbria-jwt-signing-key` | Signing/key use | Separate pharmacy-scoped certificate/key approved for RS256 only |
| Secret value | None stated | Do not introduce username/password, client secret or bearer secret |

Certificate metadata may be cataloged, but private key/PFX material remains in the provider and is never returned. The two resources are not interchangeable.

## Outbound authentication

1. Derive tenant/pharmacy/operator context from authenticated server-side state and approved metadata.
2. Prepare the first policy-bound JWT described as `Access Token`; use RS256 with the signing capability as described by the source.
3. Prepare the second policy-bound JWT described as `FSE-JWT-Signature`; use RS256 with the distinct approved signing resource described by the source.
4. Open the restricted mTLS channel using the distinct authentication certificate.
5. Apply the first JWT as bearer and the second in `FSE-JWT-Signature`, then invoke the fixed GET operation.

The term “Access Token” in the source describes a locally generated JWT, not an OAuth token exchange. No OAuth primitive is added.

## Session/token lifecycle

- **KNOWN:** two JWTs are generated/used before the healthcare API call as described by the supplied source.
- **UNKNOWN / NEEDS CHARACTERIZATION:** lifetime, reuse, regeneration frequency, replay semantics, any `jti` or nonce policy, clock skew, and the lifecycle relation between the two JWTs.
- No refresh/session service is described; absence from the source does not prove per-request generation or prohibit reuse.
- The committed fixtures use a short lifetime and one pair per synthetic dispatch solely as **SYNTHETIC TEST POLICY**. Those values are not attributed to the real service.
- Certificate revision, expiry/revocation, publication/binding change or identity mismatch invalidates channel/signing cache immediately.

## Request mapping

- REST method is documented as GET; exact path/query parameters and patient/operator/pharmacy binding are **UNKNOWN**.
- Claims are assembled only from server-derived identity, published static values and validated domain fields permitted by the profile.
- If a request digest is required, the canonicalization and covered components must be authoritative and fixed; none is assumed now.
- Sensitive query-string use is production **NO-GO** until the official contract and threat review are available.

## Response mapping

Require valid TLS, expected status, media type and bounded JSON before mapping to a typed FSE result. Do not return JWTs, certificate metadata, authentication headers or fields outside the approved response schema.

## Error mapping

| Condition | Connector category |
|---|---|
| mTLS certificate unavailable/wrong purpose/expired | `client_authentication_unavailable` |
| Server TLS trust/hostname/revocation failure | `upstream_tls_invalid` |
| Signing key unavailable/wrong purpose | `signing_unavailable` |
| Claim profile cannot be satisfied | `signing_profile_invalid` |
| JWT rejected/expired/replayed | `upstream_authentication_failed` |
| Upstream authorization denial | `upstream_access_denied` |
| 429/transient failure | `upstream_throttled` / `upstream_unavailable` |
| Malformed/oversize/unexpected JSON | `upstream_protocol_invalid` |

Exact upstream status/error payload mapping is **NEEDS CHARACTERIZATION**.

## Retry rules

- Default retry count is zero.
- The synthetic harness may create one JWT pair for each synthetic dispatch as **SYNTHETIC TEST POLICY**. Production regeneration, reuse and `jti` behavior remain **NEEDS CHARACTERIZATION**.
- Retry of GET is allowed only after official idempotency and replay behavior are confirmed and only for failures known to occur before or safely after dispatch.
- Certificate/signing/provider failures are not transport-retried with another resource version.

## Timeout

Production connect/request timeout, response limit, rate limit and maintenance behavior are **UNKNOWN**. Synthetic tests use a 30-second ceiling and bounded JSON only as test configuration.

## Redaction

Redact compact JWTs, claims containing patient/operator/pharmacy identity, certificate/key/provider reference, client-certificate chain details beyond approved metadata, query string, clinical response, endpoint, TLS diagnostics that expose infrastructure and stack traces.

## Audit

Record connector/version/operation, derived tenant/installation/application, certificate catalog versions/purposes, signing profile IDs, `jti` digest if approved, outcome category, TLS/signing stage, duration, response-size class and correlation ID. Never record compact JWT, claim values, certificate bytes, provider references or clinical data.

## Provenance

- Provided documentation: `SRC-PDF` §8.3, page 18.
- Corroborating pattern only: sanitized FSE/JWT/mTLS findings in `SRC-HTML`, `SRC-DRC` and `SRC-INF`.
- Synthetic vectors: `tests/characterization/healthcare/umbria-mtls-jwt`.
- Execution inference: ADR-0015 and ADR-0019 separate certificate/signing capabilities.

See [the provenance register](../provenance.md).

## Execution location

| Dimension | Characterization |
|---|---|
| User interaction | None stated |
| Secret/certificate custody | Gateway only if central/provider-side custody and use of both pharmacy keys/certificates are permitted |
| Token/session exchange | Two JWTs are prepared before the call; lifecycle and reuse are **NEEDS CHARACTERIZATION** |
| Healthcare API execution | Gateway invokes the REST API over mTLS |
| Mandatory local capability/hardware | None demonstrated |

**GATEWAY, conditional.** GO requires authority approval for central/provider-side custody/use of both pharmacy keys. If either key must remain non-exportable on local hardware, location becomes **HYBRID** and requires a separately approved typed local-signature design.

## Security constraints

- distinct provider capabilities and resource purposes for mTLS versus signing;
- fixed `alg=RS256`; reject `none`, HS256, algorithm/key confusion and caller headers/claims;
- server-derived pharmacy/operator/tenant authorization before provider, DNS or transport;
- bounded lifetime, clock skew and replay protection once profile is known;
- no private-key export, generic signing API, raw JWT return or certificate fallback;
- strict TLS hostname/chain/revocation policy, restricted egress and redirect denial;
- publication blocked if key custody, EKU/purpose, environment or claim profile is incomplete.

## Unresolved questions and GO gate

1. Is this profile regional-only or aligned to a named national FSE 2.0/ModI version?
2. What are exact header/JWS profiles and required claims for both JWTs, including how they differ?
3. Are request digest, canonical URL/method, `x5c/kid`, nonce and replay store required?
4. What are maximum lifetime, clock skew, issuer, audience, subject, role and pharmacy/operator binding rules?
5. What certificate subject/SAN/EKU/chain, onboarding, custody, renewal, overlap and revocation rules apply to each purpose?
6. What request/response schemas, error taxonomy, timeout, throttle and idempotency rules apply?
7. Which endpoint/trust bindings represent test and production, and are both keys permitted in a central provider?

**Writer decision:** GO for synthetic purpose-separated mTLS and RS256 primitives; NO-GO for production Umbria connector implementation until questions 1-7 are resolved.
