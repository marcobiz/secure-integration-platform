# M6 Certificate, Signing and mTLS primitives - implementation report

## Scope and baseline

- baseline: `f34275096b4960bb5f31840553444935defc3d2d` (`origin/main`, frozen M6 characterization baseline);
- branch: `m6/auth-cert-signing`;
- implementation: synthetic Wave 2 AP-05/AP-06 only;
- excluded: OAuth/PKCE lifecycle, SOAP/session, production healthcare connectors,
  inbound Broker/Direct authentication, universal KMS and Hyper-V.

PKCE remains in the independent HTTP/OAuth writer because it does not require certificate
or provider-side key-use capability.

## Capability and custody model

The Core keeps distinct provider contracts:

- `ISecretValueProvider` for server-side values;
- `IClientCertificateProvider` and `ICertificateMetadataProvider` for outbound mTLS;
- `IKeyOperationProvider` for public key metadata plus provider-side digest signing;
- separate MAC, health and capability discovery contracts already present.

There is no generic KMS and no private-key retrieval method. The signing primitive asks
the provider to sign a SHA-256 digest with fixed `RS256`, then verifies the returned
signature with the approved public SPKI. The mTLS primitive receives only an ephemeral
certificate handle suitable for the TLS channel. Missing signing or certificate
capability returns a stable fail-closed state and never triggers a Broker fallback.

FVG and Umbria remain **GATEWAY CONDITIONAL**: a deployment must offer central/provider-side
signing and client-certificate use, including remote signing for non-exportable keys.
Reclassification to Hybrid is Connector Pack work after authoritative characterization.

## Small connector-facing API

- `Rs256JwtSigner.SignJwtAsync(context, profile, claims)`;
- `PurposeBoundClientCertificateResolver.ResolveClientCertificateAsync(context, profile)`.

The profile fixes issuer, audience, subject policy, claim allowlist, lifetime, clock skew,
minimum strength and logical resource binding. The caller cannot pass algorithm, provider,
locator, key, PFX, endpoint override or privileged standard claim.

The binding resolver result is exact for Tenant/Installation/Application context plus:

- ConnectorVersion;
- Connector and operation;
- authentication profile;
- Environment;
- HTTPS endpoint;
- logical binding and distinct purpose;
- catalog revision/checksum;
- approved public fingerprint, validity, key type/size and resource version.

## RS256 and JWT policy

The signer emits only `alg=RS256`, `typ=JWT`. Issuer, audience, subject, `iat`, `nbf`,
`exp` and random `jti` are server-generated. Reserved claim override, duplicate claims,
objects/arrays, oversized values, non-allowlisted claims, excessive lifetime and unsafe
profile values fail before key use. A bounded replay store reserves only SHA-256 of each
generated `jti`. Private key bytes never enter the signing primitive.

Provider metadata must match the approved fingerprint, version, validity, RSA type and
strength. The returned signature is verified with public SPKI, denying wrong-key and
HS/RS-style provider confusion.

## Purpose-bound outbound mTLS

Client certificates require current validity, private-key use, ClientAuth EKU, Digital
Signature key usage, approved fingerprint/version and RSA/ECDSA minimum strength.
Expired, not-yet-valid, disabled, wrong-purpose and metadata-stale resources are denied.
A valid certificate inside the configured warning window returns `NearExpiry` without
automatic blocking.

The primitive has no private-key or certificate cache. Every call re-resolves the current
revision and metadata, so rotation revision 1 -> 2 stops all revision 1 use. Disable is
checked before metadata/provider/network access.

## Synthetic provider and server

`SyntheticAuthenticationMaterial` generates per run:

- RSA signing revisions 1 and 2;
- ClientAuth certificate revisions 1 and 2;
- expired and near-expiry ClientAuth certificates;
- wrong-purpose ServerAuth certificate;
- synthetic root and localhost ServerAuth certificate.

Nothing is written to the repository. Windows TLS handles are imported into the temporary
user key store for Schannel and disposed after the test; intermediate PKCS#12 bytes are
zeroed. The local `SslStream` server requires the expected client certificate. Tests use
the existing restricted transport with a pinned approved address and custom synthetic
trust root, and reject hostname mismatch and the wrong client certificate.

## Automated security evidence

The dedicated suite currently contains 31 passing tests covering RS256 positive flow,
reserved/duplicate/unsafe claims, excessive lifetime, replay, wrong key, stale metadata,
remote signing, missing capability, non-exportability surface, redaction, exact binding,
mTLS positive/expiry/purpose/near-expiry/rotation/disable, real handshake, hostname and
certificate rejection. Final repository totals, scans, SBOM, CI and review are recorded
only after the complete gate on the final commit.

## Readiness boundary

- GO for the provider-neutral synthetic AP-05/AP-06 primitives after final green gate;
- NO-GO for a production FVG or Umbria connector;
- NO-GO for claims/lifetimes/lifecycle inferred from the sanitized corpus;
- NO-GO for automatic Broker fallback or a universal KMS.
