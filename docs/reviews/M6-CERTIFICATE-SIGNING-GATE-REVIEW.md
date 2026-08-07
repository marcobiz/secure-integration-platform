# M6 Certificate, Signing and mTLS primitives - gate review

## Decision

- **GO** for primitive implementation PR review after the local and CI gates below.
- **NO-GO** to publish or claim production readiness for FVG, Umbria or another
  healthcare Connector.
- **NO-GO** for OAuth/PKCE lifecycle, SOAP/session, inbound authentication changes,
  automatic Broker fallback or a universal KMS in this branch.

This review covers synthetic AP-05/AP-06 capability only. The original PR CI is green;
the targeted four-finding remediation requires a new exact-head CI pass and independent
delta review. The PR must not be auto-merged.

## Lineage and scope

| Item | Value |
|---|---|
| Frozen baseline | `f34275096b4960bb5f31840553444935defc3d2d` |
| Branch | `m6/auth-cert-signing` |
| Pull request | `#11` |
| Initial remediated-from HEAD | `eee40668e01ef2ec75155e4d7edfb54ff11434e5` |
| Worktree | `C:\Codice\broker-gateway-m6-cert` |
| Migration change | None |
| Admin Web/API change | None |
| Healthcare production code | None |
| Inbound Broker/Direct authentication change | None |

## Architecture and custody review

- Core module depends only on provider-neutral `Providers.Abstractions`; a narrow adapter
  in `Gateway.Infrastructure` bridges an opaque non-constructible certificate lease to the
  existing restricted transport.
- `IKeyOperationProvider` is a narrow provider-side signing capability with public
  metadata; no private-key export or generic KMS operation exists.
- `IClientCertificateProvider` and `ICertificateMetadataProvider` remain separate from
  signing and secret retrieval.
- Missing central signing/certificate capability is a stable fail-closed state. There is
  no fallback to the Broker and no dependency on `InstallationKind`.
- FVG/Umbria execution is therefore **GATEWAY CONDITIONAL** on approved central/provider
  custody. A future Hybrid decision belongs to a Connector Pack ADR/threat review.

## RS256/JWT review

- fixed `alg=RS256` and `typ=JWT`;
- connector call accepts only logical policy ID and allowlisted business claims;
- issuer, audience, subject policy, lifetime, skew, allowlist and logical key binding are
  resolved from an immutable server-owned policy snapshot;
- policy revision and recomputed checksum must match the exact resource binding before
  provider metadata or signing calls;
- standard security claims are server-generated and cannot be overridden;
- duplicate/unapproved/structured/oversized claims fail before key use;
- bounded SHA-256-only `jti` replay cache;
- approved fingerprint/version/validity/RSA strength and SPKI SHA-256 checks;
- the exact SPKI identity that passed the approved digest check verifies the provider
  result, covering scalar-fingerprint/SPKI substitution, wrong-key and HS/RS confusion;
- metadata/sign failures, including unexpected exceptions, collapse to metadata-safe
  stable codes without provider message or inner exception.

## mTLS review

- exact binding to ConnectorVersion, Connector/operation, profile, Environment, endpoint,
  logical purpose and catalog revision/checksum;
- DER fingerprint, SPKI digest, resource version, validity, key algorithm/strength,
  ClientAuth EKU and Digital Signature key usage enforced;
- expired/not-yet-valid/disabled/wrong-purpose/stale metadata denied;
- near-expiry returns a warning without automatic denial;
- no certificate-returning public API or reusable handle: policy, binding, revision,
  status, endpoint and request method are revalidated immediately before DNS/dispatch;
- no certificate/private-key cache; rotate, disable, retained rev1 and endpoint
  substitution deny before dispatch;
- real local TLS server requires the expected client certificate; wrong hostname and
  wrong certificate fail the handshake through restricted transport.

## Local deterministic evidence

| Gate | Result |
|---|---|
| `eng/build.ps1` | PASS, 0 warnings/errors |
| `eng/test.ps1` | PASS: 211 ordinary tests; 10 PostgreSQL/full-stack conditional skips |
| M6 dedicated suite | PASS: 49/49 |
| Architecture suite | PASS: 10/10 |
| Azure optional pack build/test | PASS: build + 1/1 test |
| Documentation validation | PASS |
| Conservative secret scan | PASS |
| SBOM generation/validation | PASS, includes `auth-certificate-signing.spdx.json` |
| SBOM mode regression | PASS |
| Vulnerable transitive packages | None reported |
| Core OSS export | Remediation staged-content PASS: 326 files; manifest SHA-256 `2CF47BAE4AFEC9ED1B72E9FAC400772503D9C146E8C8D2EDF1E59F165ABCE88D` |
| Core export frontend regression | PASS: lint, 28/28 Vitest, build, license scan |
| `git diff --check` | PASS |

The ten ordinary-suite skips are the repository's explicit PostgreSQL/full-stack tests;
they are exercised by dedicated CI jobs. No schema, migration, locator function or Admin
surface changed in this branch.

## CI and publication

PR `#11` is open without merge. CI ran on the product and local-gate commit
`8ab5a4d07f4858bd0a0548725282d4c4bcfb83f3`:

- workflow `ci`, run `31194728177`: PASS, including Windows build/test, Gitleaks,
  PostgreSQL 18, Gateway container, M3 deterministic slice and M4 quick start;
- workflow `m5-admin-ui`, run `31194729082`: PASS, including secret/license scans,
  SBOM, open-source boundary export, PostgreSQL 18, UI/API tests, browser/full-stack,
  UI container and clean-clone quick start.

All 21 reported PR checks passed. This CI evidence is separate from the local
deterministic evidence above and does not change production healthcare readiness from
NO-GO. It predates the targeted remediation and is not evidence for the delta. The
remediation commit and its documentation publication commit must pass the same PR
workflows before hand-off.

## Targeted four-finding remediation

| Finding | Local delta result |
|---|---|
| HIGH server-owned RS256 policy | Closed: same-ID issuer/audience/subject/lifetime/allowlist substitution is denied before provider calls |
| HIGH reusable mTLS handle | Closed: connector-facing API is one-shot transport-bound; retained rev1, disable and endpoint substitution produce zero dispatch |
| MEDIUM fingerprint/SPKI binding | Closed: approved SPKI digest is checked and that exact SPKI verifies the signature; malicious substituted SPKI is denied before sign |
| MEDIUM provider exception sanitization | Closed: unexpected metadata/sign/certificate exceptions are replaced by stable codes; genuine cancellation remains cancellation |

## Residual risk

- no real cloud/provider signing or hardware-backed key was qualified;
- no authoritative FVG/Umbria claims, certificate policy, revocation behavior or token
  lifecycle was supplied;
- the Gateway/provider host remains in the TCB and Administrator/SYSTEM remains a
  residual privileged threat;
- an official Connector profile and four-eyes-approved binding are still required before
  any production invocation path exists.
