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
signature with the exact SPKI identity approved by its SHA-256 digest. The mTLS sender
keeps the certificate handle inside one transport operation and disposes it after
dispatch. Missing signing or certificate capability returns a stable fail-closed state
and never triggers a Broker fallback.

FVG and Umbria remain **GATEWAY CONDITIONAL**: a deployment must offer central/provider-side
signing and client-certificate use, including remote signing for non-exportable keys.
Reclassification to Hybrid is Connector Pack work after authoritative characterization.

## Small connector-facing API

- `Rs256JwtSigner.SignJwtAsync(context, policyId, businessClaims)`;
- `PurposeBoundMutualTlsSender.SendAsync(context, policyId, approvedRequest)`.

The connector-facing caller supplies only a logical policy ID and bounded business input.
`IAuthenticationPolicySource` resolves the immutable server-owned policy for the exact
Published ConnectorVersion and operation. The caller cannot pass issuer, audience,
subject policy, lifetime, allowlist, algorithm, provider, locator, key, PFX, endpoint
override or privileged standard claim.

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

The signer first resolves a policy snapshot containing policy revision/checksum, exact
ConnectorVersion/operation/Environment/endpoint, issuer, audience, subject policy,
lifetime/skew, claim allowlist, logical key binding, catalog revision/checksum and resource
revision. The snapshot digest is recomputed and must match the exact identity frozen into
the resource binding before any provider call. `ResolvedRs256SigningContext` is internal
and cannot be constructed or supplied by a Connector.

The signer emits only `alg=RS256`, `typ=JWT`. Issuer, audience, subject, `iat`, `nbf`,
`exp` and random `jti` are server-generated. Reserved claim override, duplicate claims,
objects/arrays, oversized values, non-allowlisted claims, excessive lifetime and policy
substitution fail before key use. A bounded replay store reserves only SHA-256 of each
generated `jti`. Private key bytes never enter the signing primitive.

Provider metadata must match the approved fingerprint, version, validity, RSA type and
strength. The SHA-256 digest of the returned SPKI must match the separately approved SPKI
digest. That exact SPKI is copied into the resolved context and used to verify the returned
signature, denying scalar-fingerprint plus substituted-SPKI attacks, wrong-key and
HS/RS-style confusion.

ADR-0028 adds one bounded signing-certificate Key Usage requirement without relaxing the
historical signer. `DigitalSignature` remains the default and keeps the original behavior:
an absent Key Usage extension is accepted, while a present extension must contain
`digitalSignature`. `ContentCommitment` is explicit, policy-digest-bound and requires a
present extension containing `contentCommitment`/`nonRepudiation`. The branches are not an
OR, and no subject, issuer, OID, slot or connector metadata selects the mode.

## Purpose-bound outbound mTLS

Client certificates require current validity, private-key use, ClientAuth EKU, Digital
Signature key usage, approved DER fingerprint, approved SPKI digest/version and RSA/ECDSA minimum strength.
Expired, not-yet-valid, disabled, wrong-purpose and metadata-stale resources are denied.
A valid certificate inside the configured warning window returns `NearExpiry` without
automatic blocking.

The primitive has no private-key or certificate cache and no certificate-returning API.
`PurposeBoundMutualTlsSender` owns resolve, validation, attachment and dispatch. It
re-resolves policy and binding after certificate validation and immediately before DNS
and transport, then compares policy/catalog/resource identities. Rotation revision 1 -> 2,
disable, endpoint substitution or a stale revision 1 certificate therefore deny before
network dispatch.

## Provider boundary sanitization

Metadata, signing and certificate provider calls preserve a genuine caller cancellation
only when the supplied cancellation token is canceled. Every other provider exception,
including unexpected SDK exceptions, is replaced by a stable
`AuthenticationPrimitiveException` containing no provider message, inner exception,
locator, token, credential or SDK detail.

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

The dedicated suite contains 49 passing tests. In addition to the original RS256, claim,
replay, rotation, certificate-purpose, hostname and real mTLS coverage, it now proves
same-ID issuer/audience/subject/lifetime/allowlist substitution denial with zero provider
sign calls; malicious fingerprint/SPKI substitution denial; retained revision 1 and
endpoint substitution denial before dispatch; one-shot disable revalidation; restricted
egress; public API non-exposure; and unexpected provider exception sanitization at
metadata, signing and certificate boundaries.

## Readiness boundary

- GO for the provider-neutral synthetic AP-05/AP-06 primitives after final green gate;
- NO-GO for a production FVG or Umbria connector;
- NO-GO for claims/lifetimes/lifecycle inferred from the sanitized corpus;
- NO-GO for automatic Broker fallback or a universal KMS.
