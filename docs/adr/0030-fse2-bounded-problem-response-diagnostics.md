# ADR-0030: FSE2 bounded problem-response diagnostics

**Status:** Accepted

## Context

The frozen FSE2 guide requires `Accept: application/json` on validate-cda, but the qualified
restricted-transport path did not project that header. The same path also collapsed every upstream
HTTP non-success response and every DNS, TCP, TLS, mutual-TLS or timeout failure into the same
sanitized Gateway error before `Fse2ResponseMapper` could classify a bounded problem response. The
previous live evidence therefore proves only `UPSTREAM_OR_TRANSPORT_FAILURE_UNCLASSIFIED`; it does
not prove an upstream HTTP rejection or an OfficialTest problem code.

A general header bag, a caller-selected response mode or raw upstream response logging would widen
authority and disclosure beyond the narrow contract correction. Other restricted-transport callers
already depend on the existing fail-closed non-success behavior.

## Decision

- A closed `AuthorizedRestrictedTransportResponseMode` is part of the module's bounded Published
  operation expectations. Its default is the historical `SuccessOnly`; FSE2 alone requires
  `BoundedProblemDetails`. Core exact-matches and retains that mode only after the full authoritative
  Published preflight succeeds. The mode is not caller or request-payload input.
- Core projects exactly one server-owned `Accept: application/json` value only for that qualified
  mode. No generic header collection, header name or header value surface is introduced. Endpoint,
  method, content type, retry zero, redirect zero, certificates and signing policies remain
  Published/Core authority.
- `IRestrictedTransport.SendAsync` preserves its historical semantics. A separate bounded-problem
  operation is selected only by the qualified FSE2 path. It may return a non-success response with
  status, content type and at most 16 KiB of body; redirects remain denied and an oversized body is
  collapsed without retaining its bytes.
- `Fse2ResponseMapper` may retain only a code/type from the frozen official allowlist. Duplicate,
  malformed, non-object, unknown-code and oversized problems collapse safely. `title`, `detail`, raw
  body, URL, JWT, certificate and exception text are never returned, audited or evidenced.
- DNS, TCP connect, TLS server validation, mutual-TLS client authentication, timeout and other
  transport failures use a closed internal phase. An upstream HTTP response uses
  `UPSTREAM_HTTP_RESPONSE` plus the bounded status/category and optional allowlisted FSE2 code.
  Application audit receives only correlation, operation, connector version, caller kind and these
  safe diagnostics. The caller still receives the existing generic sanitized Problem.
- The public capability bridge gains one narrow exact-result rejection operation. It accepts only
  the same response object returned by the invocation's single bounded transport call, only inside
  the current qualified scope, only for non-success status, and only with the mapper's bounded safe
  code. It cannot acquire an endpoint, header, policy, transport, response body or second dispatch.
- The frozen case 476 request contract is reconstructed offline against the sealed plan and official
  baseline. No OfficialTest DNS resolution or network dispatch is part of this decision evidence.

## Consequences

FSE2 receives the required server-owned media-type preference and can distinguish a bounded upstream
HTTP response from transport phases without exposing the response. Existing non-FSE2 callers and
the historical transport entry point keep their exact failure semantics. The change remains
vertical-neutral in Core: Core understands only a closed response mode and safe transport phases,
not FSE2 codes or healthcare concepts.

This ADR narrows the alternative rejected by ADR-0027 concerning public bridge validation methods:
no general validation or policy-inspection surface is added, but one exact-result failure-reporting
operation is now accepted because otherwise the module mapper cannot safely classify the already
returned response. ADR-0027 remains unchanged for every other authority boundary.

An HTTP response received after dispatch cannot make the outbound effect reversible. The phase is a
safe operational classification, not a claim about external root cause. Gateway/provider process,
local Administrator/SYSTEM, proxy behavior and privileged dumps remain residual threats.

## Alternatives rejected

Caller-owned or generic headers, FSE2-specific types in Core, changing `SendAsync` for every caller,
returning arbitrary non-success bodies, logging raw RFC 7807 data, matching exception messages,
automatic retry, redirect following, and retroactively treating the previous live result as a
proved HTTP rejection.
