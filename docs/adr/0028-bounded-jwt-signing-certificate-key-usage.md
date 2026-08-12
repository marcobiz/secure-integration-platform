# ADR-0028: Bounded JWT signing-certificate Key Usage

**Status:** Accepted

## Context

The historical provider-neutral RS256 signer accepts an X.509 signing certificate without a Key
Usage extension and, when the extension is present, requires `digitalSignature`. The officially
assigned FSE2 S1 JWT-signing certificate instead has a critical Key Usage containing
`contentCommitment` (`nonRepudiation`) without `digitalSignature`.

A global `digitalSignature OR contentCommitment` check would silently relax every existing signing
profile. Inferring an exception from a certificate subject, issuer, OID, slot name or connector
would also move vertical policy into Core and make the accepted use dependent on unreviewed
certificate metadata.

## Decision

- Core defines the closed `JwtSigningCertificateKeyUsageMode` values `DigitalSignature` and
  `ContentCommitment`. The existing public RS256 policy factory remains available and maps exactly
  to `DigitalSignature`; a typed overload is the only way to request another mode.
- The RS256 policy digest always covers the effective mode. Undefined enum values are invalid.
- `invocationSigning.certificateKeyUsage` is an optional Published member with only
  `digitalSignature` and `contentCommitment`. Absence maps explicitly to the historical
  `DigitalSignature` mode and does not rewrite or change the canonical checksum of an existing
  definition. When present, the member participates in canonical checksum and four-eyes approval.
- The public external-module expectation contract gains the parallel closed
  `AuthorizedSigningCertificateKeyUsageMode`. Its existing constructor remains available and maps
  to `DigitalSignature`. Core compares the expectation with the effective Published mode during the
  mandatory preflight before capability scope, strategy, signing, DNS or network.
- In `DigitalSignature` mode the signer preserves the historical rule exactly: an absent Key Usage
  extension is accepted; a present extension must contain `digitalSignature`.
- In `ContentCommitment` mode the signer requires a present Key Usage extension containing
  `contentCommitment`/`nonRepudiation`. Public certificate material is therefore mandatory even
  when the policy does not emit `x5c`.
- The modes are separate branches, not an OR. Core does not infer a mode from subject, issuer,
  certificate OID, slot, connector or industry profile.
- The FSE2 Organization expectation requires `ContentCommitment` for both `authorization` and
  `integrity`. Both retain one S1 signing identity. The distinct A1 client-authentication identity
  and its historical mTLS `DigitalSignature` requirement are unchanged.

## Consequences

Existing profiles retain their exact certificate acceptance behavior and Published JSON checksums.
A new explicit profile may use an officially assigned content-commitment signing certificate
without weakening any other RS256 policy. A Published/expectation mismatch is denied before all
privileged and network effects, while an A-to-B change after preflight remains denied by the
existing exact-A freshness checks before private-key signing or transport.

The change does not alter private-key custody, provider resolution, chain construction, leaf-first
`x5c`, algorithm selection, restricted transport, endpoint authority, mTLS validation or certificate
locator behavior. Trust, revocation, operational import and live service qualification remain
deployment and accreditation controls outside this decision.

## Alternatives rejected

Global `digitalSignature OR contentCommitment`, accepting either flag implicitly, treating a
missing Key Usage as content commitment, certificate-subject/issuer/OID heuristics, FSE2-specific
branches in Core, CA/fingerprint pinning in source, changing the mTLS Key Usage rule, and operational
certificate import as part of the software change.
