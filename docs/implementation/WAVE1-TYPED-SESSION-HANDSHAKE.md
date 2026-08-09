# Wave 1 typed session handshake and authorized external admission

## Scope and baseline

- Base: `705e9d4bd203ca7b902ad0aeedc9d4402f9f4452`.
- Branch: `wave1/auth-session-handshake`.
- Core capability only: typed nested SOAP session bootstrap plus authorized external opaque-session
  admission.
- Existing M6 scalar Login/Challenge/Business/Logout profiles remain the default compatibility
  path.
- No new cache, distributed state, generic XML mapper, deployment pack or production connector is
  introduced.

## Published authority and adapter model

`PublishedTypedSessionHandshakeResolver` accepts `AuthorizedGatewayInvocation` and a
`TypedSessionHandshakeAuthorityRequest` containing only the logical profile ID. It reads the exact
operation from the current Published snapshot and produces a non-forgeable
`ResolvedTypedSessionHandshake`.

The `typedSessionHandshake` definition member is checksum/four-eyes controlled and fixes:

- request and response adapter logical ID/type;
- exact request and response QName;
- SOAP 1.1 or 1.2 and exact action;
- handshake endpoint/path, timeout and request/response bounds;
- local maximum session lifetime;
- optional validator ID/type, validation endpoint/path, intent TTL, timeout and response bound.

The immutable authority fingerprint also covers ConnectorVersion ID/version/checksum, publication
revision, binding checksum/revision, resource stamp, credential resource revisions, operation and
profile. Registry lookup is exact and uses no CLR reflection.

The request adapter receives a Core-owned `XmlWriter` already inside the exact request element and
an immutable `TypedSessionHandshakeRequestContext`. The context contains authenticated identity and
Published metadata only; there is no arbitrary dictionary or ordinary business payload. A bounded
write stream stops output at the Published request limit.

The response path first applies the existing hardened XML reader settings and structural SOAP
checks. Only the expected payload is exposed through `XmlReader` to the compiled response adapter.
The adapter performs protocol-specific nested validation and returns the closed
`TypedSessionHandshakeAdapterOutcome`.

## Authorized external admission

`ExternalSessionAdmissionIntent` is created by Core only after the typed bootstrap returns
`ExternalAdmissionRequired`. It carries an opaque reference plus safe provenance/expiry metadata;
the cache retains only its digest and exact authority binding.

`ExternalSessionCandidate` is a dedicated presentation type with an owned, bounded UTF-8 buffer.
The completion method consumes and clears it on every terminal path. Candidate, admitted value,
validator body and remote diagnostics are absent from exceptions, `ToString`, JSON and audit
metadata.

The sequence is:

1. revalidate Published authority and the existing session resource stamp;
2. reserve the exact intent once in the existing cache;
3. call the profile-selected validator with the sensitive candidate and exact validation context;
4. revalidate Published authority and resource stamp after the remote await;
5. verify the reserved interaction and session generation are still current;
6. cap valid remote expiry by the Published local maximum;
7. atomically promote the candidate as the one current generation in `SoapSessionCache`.

Validation rejection/failure, cancellation, expiry, reuse, cross-context/profile/key mismatch,
rotation or disable abandons the intent and never promotes a session.

## Synthetic protocol and verification matrix

The neutral HTTPS synthetic server supports nested `CreateSessionRequest` /
`CreateSessionResponse` and `ValidateSessionRequest` / `ValidateSessionResponse` alongside the
unchanged legacy operations. It verifies exact nested request order and registers an externally
validated candidate so a subsequent session-authenticated business operation proves lifecycle
reuse.

Named tests cover Published adapter selection; nested request/response; strict order, cardinality,
domain, duplicate, unexpected, mixed-content and nested denial; DTD/QName/Body hardening; direct
issuance; external handoff; wrong/reused/expired/cross-context/profile intent; validation failure;
remote-expiry validation/capping; rotate/disable race; request bound; 256-key cap/lazy sweep;
redaction; real TLS; subsequent session use; architecture neutrality; and the complete legacy SOAP
regression.

The local full-suite, PostgreSQL 18, scan, SBOM and vulnerability evidence is recorded in the
testing report. Core export, exact-head CI and independent review are qualified only after the
thematic commits and branch publication; no merge is part of this implementation step.
