# M6 SOAP/Basic/Session authentication primitives — implementation report

## Baseline and scope

- frozen baseline: `f34275096b4960bb5f31840553444935defc3d2d` (`origin/main` as of 2026-08-07);
- branch: `m6/auth-soap-session`;
- implemented: AP-01 server-side HTTP Basic, AP-02 opaque interaction/session, AP-07 SOAP/XML boundary, login, cache, expiry, one controlled reacquisition, retry policy, logout/invalidation and Fault mapping;
- excluded: OAuth, inbound Gateway authentication, certificate/signing, production healthcare connectors, generic WS-Security/SAML/XML-DSig and arbitrary SOAP scripting.

## Implemented boundary

`Gateway.ConnectorRuntime.Auth.Soap` is a separate Core assembly. It depends on
`Gateway.Application` only for clock, DNS, restricted transport and egress
policy, and on `Providers.Abstractions` for secret use. It does not depend on Infrastructure,
Gateway API, Broker, database, cloud providers or healthcare packs.

The connector-facing profile is declarative and bounded:

- operation ID, SOAP 1.1/1.2, exact action and request/response QNames;
- logical-field allowlist with QNames and character bounds;
- login/challenge/business/logout operations;
- exact session extraction and SOAP header placement;
- explicit fault-code mapping and retry-after-reacquisition.

There is no caller input for endpoint, Basic header, username/password, session ID,
SOAPAction, namespace policy, certificate or provider locator. The HTTPS endpoint and
revisions derive from the server-side binding.

## Basic and session lifecycle

`ServerBoundBasicAuthentication` retrieves username and password only immediately
before send, rejects pre-existing headers and clears the temporary UTF-8 buffer. No
plaintext enters cache, exceptions or metadata.

The lifecycle is:

```text
credential binding -> login -> opaque session ref -> business call
-> local/upstream expiry -> invalidate -> at most one reacquisition
-> business retry only when compiled operation policy permits -> logout/invalidate
```

The cache key includes Tenant, Installation, Application, Connector/version,
Environment, binding revision, endpoint revision, credential revision and auth/session
profile. The cache contains at most 256 keys and, for each key, only one interaction and
one current session generation. Completion reserves an interaction only
once and atomically promotes the new generation, invalidating the previous digest;
a lazy sweep restricted to the bounded entries removes expired sessions/interactions.

Before resolution and immediately before use,
`ISoapSessionResourceStampProvider` must confirm an `Active` credential resource,
current credential revision, binding revision and endpoint revision. Disable and rotate
fail before secret provider, DNS, login or business transport. The module does not
assume Broker, UX, pub/sub or distributed cache.

## SOAP/XML boundary

- deterministic UTF-8 serialization without XML declaration or indentation;
- SOAP 1.1 `text/xml` plus quoted `SOAPAction` header;
- SOAP 1.2 `application/soap+xml` with action parameter and no SOAPAction header;
- HTTPS restricted transport, DNS/IP pinning, no redirect/proxy/cookies, distinct timeout and cancellation;
- linked deadline across connect/request, headers, bounded response body and parsing;
- bounded responses and requests;
- `DtdProcessing.Prohibit`, null resolver, entity/document bounds;
- explicit limits on depth, node count, attributes per element and total attributes;
- exact Envelope/Body/response/fault QNames, duplicate/unexpected elements denied;
- exact SOAP 1.1/1.2 Fault cardinality/order; duplicate, mixed and ambiguous structures denied;
- Fault detail never propagated: only a sanitized typed category; an ambiguous Fault does not trigger re-login.

## Synthetic SOAP server

`tools/m6/SyntheticSoapServer` starts Kestrel on a dynamic HTTPS loopback port with
per-run synthetic certificates. It implements Login, optional challenge completion,
BusinessOperation, Logout, session expiry/invalid session, typed Fault, malformed XML,
oversize, pre-header timeout and stalled body after synchronized header flush, with login/challenge/business/logout counters. The test client uses
root trust and certificate pinning; it does not disable TLS validation.

## Targeted local evidence

| Suite | Cases | Result |
|---|---:|---|
| `SoapAuthenticationTests` | 14 | PASS |
| `SoapRealHttpIntegrationTests` | 5 | PASS |
| `SoapAuthBoundaryTests` | 2 | PASS |
| Targeted total after remediation | 21 | PASS |

Tests cover Basic/session redaction, stale/fixation, rotate/disable, DTD/XXE/external
entity, oversize, malformed XML, namespace confusion, SOAPAction/Content-Type mismatch,
timeout/cancellation, binding manipulation, SSRF, SOAP 1.1/1.2, challenge, logout and
Fault, cache bounded over 100/1000 interactions, concurrent completion, current generation,
disable/rotate through a real stamp, stalled body after header flush and duplicate/mixed Faults.

On the remediation candidate, the full Release gate executed 192 cases: 182 PASS,
10 SKIP belonging to the already conditional PostgreSQL 18/dedicated gates and 0 failures.
Also PASS: `validate-docs`, secret scan, SPDX SBOM (including container image with 162
indexed packages), transitive vulnerability scan and `git diff --check`. The first full
run had found a test timeout threshold shared with the oversized case; the
cause was separated into a latency-specific profile and the entire gate was rerun
green on the new commit. The first PR CI also found a nondeterministic expiry
under load and the synthetic server missing from the Core export
allowlist. The test now uses a single explicit expiry and the architecture gate constrains
the allowlist; `Export-OpenSourceCore.ps1` was rerun in full with PASS
(324 files). The authoritative exact-head status remains the one associated with the PR.

## Review

GO for review of the synthetic AP-01/AP-02/AP-07 writer. NO-GO for SOGEI or other
production healthcare connectors until WSDL/schema, auth profile, lifecycle, fault taxonomy,
environment and MFA semantics are characterized and approved separately.
