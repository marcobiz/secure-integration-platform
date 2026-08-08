# Wave 1 generic JWT/X.509 extensions

## Scope and baseline

- baseline and tag target: `6e1a7c626e0e24d0a385c611fc03faef51598889`,
  `m6-auth-foundation-baseline-20260808`;
- branch: `wave1/auth-jwt-x509`;
- capability delta: public X.509 material, typed server-owned `x5c`, exact temporal
  claim inclusion and typed trusted identity sources;
- no change to inbound authentication, OAuth/session, lifetime/skew, mTLS transport,
  database schema or connector orchestration.

This is a provider-neutral Core extension. It is not an FSE2 implementation and does
not characterize or authorize a production connector.

## Public X.509 material capability

`ICertificatePublicMaterialProvider.GetPublicMaterialAsync(logicalReference, token)`
returns a defensively copied `ProviderCertificatePublicMaterial` containing only:

- the DER leaf certificate;
- zero or more DER issuer certificates in certification order, excluding the leaf;
- public certificate metadata and resource version;
- a SHA-256 SPKI identity derived from the returned leaf DER.

The contract has no private-key, PFX/PKCS#12, password, secret, provider credential,
locator-enumeration or arbitrary certificate-enumeration method. The signer calls this
provider capability only after resolving the exact server-owned JWT signing resource for
the authenticated Tenant/Installation/Application, Published ConnectorVersion,
operation, profile, Environment, policy revision/checksum, catalog revision/checksum and
`JwtSigning` purpose. A connector still cannot supply a provider reference or DER.

## Protected-header model

`JwtCertificateHeaderMode` is part of the immutable policy digest and has three accepted
values:

- `None` (the backward-compatible default);
- `Leaf`;
- `Chain`.

The protected header remains a fixed typed writer: `alg=RS256`, `typ=JWT` and, only when
the policy opts in, `x5c`. There is no generic header dictionary. `x5c` is a JSON array,
uses standard Base64 over DER (not Base64Url), and is emitted leaf first. `Chain` requires
a non-empty, bounded issuer sequence whose order and signatures build as the presented
certification path.

## Cryptographic identity binding

For an opted-in `x5c` policy, the signer parses the actual leaf DER and independently
derives its SHA-256 fingerprint, RSA SPKI, SHA-256 SPKI digest, validity, subject, issuer,
key algorithm and size. Constant-time comparisons bind that identity to both the
approved `BoundResourcePublicMetadata` and the provider signing metadata. The SPKI
derived from that same verified leaf is then used to verify the provider's RS256 result.

Consequently, approved scalar metadata combined with substituted DER, substituted SPKI
or signing under the substituted key is denied. An unrelated or reordered chain is also
denied. Public material is bounded to one leaf, at most seven issuer certificates and
256 KiB total encoded DER.

## Temporal inclusion

`JwtTemporalClaimMode` is also policy-digest-bound:

- `IssuedAtNotBeforeExpiration` preserves the M6 default (`iat`, `nbf`, `exp`);
- `IssuedAtExpiration` emits `iat` and `exp` and omits `nbf` exactly.

Both modes reuse the existing lifetime and clock-skew policy. Lifetime remains bounded
to the existing maximum and drives `exp`, signing-certificate validity and replay-store
expiry. Undefined temporal modes fail before binding or provider use. No new
lifetime/skew subsystem was introduced.

## Trusted subject and claim sources

The subject policy now also supports authenticated Tenant identity, alongside the
existing authenticated Installation, authenticated Application and fixed server value.
`JwtTrustedClaimBinding` maps a policy-owned claim name to exactly one typed source:

- `AuthenticatedTenantId`;
- `AuthenticatedApplicationId`;
- `AuthenticatedInstallationId`.

These values come from `AuthenticationExecutionContext`, which is populated from the
server-derived `GatewayClientPrincipal` path. There is no runtime dictionary, reflection
path, expression language, JSONPath or caller-selected context property. Trusted claim
names cannot be registered/protected fields, cannot overlap the business-claim allowlist
and cannot be duplicated. Caller business claims remain separately allowlisted and
cannot override `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, `alg`, `x5c` or other
reserved JWS fields.

## Rotation, disable and provider failures

Policy and binding authorization are re-resolved after metadata/public-material reads,
immediately before provider signing, and again before returning the compact token. Exact
policy checksum, catalog stamp, provider reference, resource version, fingerprint and
SPKI identity must remain unchanged. Rotation or disable therefore prevents stale `x5c`
or a stale authenticated token from escaping; a retained revision-one public-material
capability cannot authenticate revision two.

Unexpected non-cancellation failures at metadata, public-material and sign boundaries
become stable `AuthenticationPrimitiveException` codes with no provider message or inner
exception. Genuine caller cancellation remains `OperationCanceledException`.

## Connector-facing API and frozen exclusions

The connector-facing call remains:

`SignJwtAsync(AuthenticationExecutionContext, policyId, allowedBusinessClaims, token)`.

It accepts no DER, certificate handle, `x5c`, protected-header map, provider locator,
subject override, lifetime, skew or algorithm.

- Dual JWT orchestration = **CONNECTOR_RESPONSIBILITY**.
- Service-specific issuer/CN composition = **CONNECTOR_RESPONSIBILITY**.
- CX/XON/IHE identifiers = **CONNECTOR_RESPONSIBILITY**.
- Document hash orchestration = **CONNECTOR_RESPONSIBILITY**.
- Lifetime/skew system = **ALREADY_EXISTS**.

Certificate subject/CN remains safe public metadata. No rule composes an issuer or
business identity from CN in Core.

## Local automated evidence

- `Authentication.CertificateSigning.Tests`: 68/68 PASS, including 19 new/extended
  executions for leaf/chain/Base64, injection denial, substituted leaf/chain,
  fingerprint/SPKI/signature mismatch, stale revision, rotate/disable, exact temporal
  omission, trusted-source policy, provider redaction and cancellation;
- `Architecture.Tests`: 17/17 PASS, including the capability/public-API boundary,
  absence of a generic protected-header bag and generic-only source/test guard;
- full Release build: PASS with zero warnings and zero errors;
- ordinary repository suite: 281 PASS and 10 expected conditional PostgreSQL skips.

The final PostgreSQL qualification, scans, SBOM, Core export and exact-head CI are
recorded only after their respective gates complete.
