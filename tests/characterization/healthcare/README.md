# Healthcare characterization fixtures

This directory contains non-operational, fully synthetic fixtures for four
healthcare connector characterizations. The fixtures exercise parsing and
state transitions only. They are not wire-compatible examples and must not be
used to infer undocumented provider behavior.

All URI-shaped identifiers use `urn:example`; all HTTP hosts use
`example.test`. Authentication material is represented by non-resolvable
references. The corpus intentionally contains no usable credential, compact
JWT, certificate bytes, or private material.

## Corpus

- `sogei-basic-session`: a SOAP-shaped login request, accepted response,
  session-expired fault, and separate session-reference metadata.
- `lombardia-oauth-helper`: helper-session metadata, a synthetic OAuth token
  response, and an expired-token error.
- `fvg-pkce-jwt`: a coherent S256 PKCE pair, synthetic token response,
  decoded JWT claims, and OAuth error.
- `umbria-mtls-jwt`: metadata for distinct mTLS and signing certificate
  purposes, two decoded JWT profiles, and expired-JWT/mTLS errors.

Execution-location metadata records SOGEI and Lombardia as `gateway` and
FVG as `gateway-conditional` on central/provider-side signing-key custody.
The five-minute Umbria claim lifetime and one-pair-per-synthetic-dispatch
behavior are labeled **SYNTHETIC TEST POLICY**. They test expiry and profile
separation only and do not claim provider lifetime, reuse, regeneration,
replay, `jti`/nonce or clock-skew behavior.

The XML namespace is deliberately an `urn:example` namespace. It preserves
the envelope/fault shape needed by parsers without claiming a real provider
contract.

## Validation

From the repository root, on Windows PowerShell 5.1 or later:

```powershell
./tests/characterization/healthcare/validate-fixtures.ps1
```

The validator parses every JSON/XML fixture, verifies the PKCE S256 pair,
checks the expected corpus shape, and fails if fixture data contains a compact
JWT, private/certificate material, a non-example HTTP host, or a non-example
URN namespace.
