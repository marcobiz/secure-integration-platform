# M6 Certificate, Signing and mTLS primitives - gate review

## Decision

- **GO** for primitive implementation PR review after the local and CI gates below.
- **NO-GO** to publish or claim production readiness for FVG, Umbria or another
  healthcare Connector.
- **NO-GO** for OAuth/PKCE lifecycle, SOAP/session, inbound authentication changes,
  automatic Broker fallback or a universal KMS in this branch.

This review covers synthetic AP-05/AP-06 capability only. The PR CI is green; a final
merge decision still requires independent review. The PR must not be auto-merged.

## Lineage and scope

| Item | Value |
|---|---|
| Frozen baseline | `f34275096b4960bb5f31840553444935defc3d2d` |
| Branch | `m6/auth-cert-signing` |
| Pull request | `#11` |
| Product and local-gate commit | `8ab5a4d07f4858bd0a0548725282d4c4bcfb83f3` |
| Worktree | `C:\Codice\broker-gateway-m6-cert` |
| Migration change | None |
| Admin Web/API change | None |
| Healthcare production code | None |
| Inbound Broker/Direct authentication change | None |

## Architecture and custody review

- Core module depends only on `Providers.Abstractions`.
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
- fixed issuer, audience, subject policy, lifetime, skew and logical key binding;
- standard security claims are server-generated and cannot be overridden;
- duplicate/unapproved/structured/oversized claims fail before key use;
- bounded SHA-256-only `jti` replay cache;
- approved fingerprint/version/validity/RSA strength checks;
- provider result verified with approved public SPKI, covering wrong-key and HS/RS
  confusion;
- provider failures collapse to metadata-safe stable codes without inner exceptions.

## mTLS review

- exact binding to ConnectorVersion, Connector/operation, profile, Environment, endpoint,
  logical purpose and catalog revision/checksum;
- fingerprint, resource version, validity, key algorithm/strength, ClientAuth EKU and
  Digital Signature key usage enforced;
- expired/not-yet-valid/disabled/wrong-purpose/stale metadata denied;
- near-expiry returns a warning without automatic denial;
- no certificate/private-key cache; revision and status are resolved per use;
- real local TLS server requires the expected client certificate; wrong hostname and
  wrong certificate fail the handshake through restricted transport.

## Local deterministic evidence

| Gate | Result |
|---|---|
| `eng/build.ps1` | PASS, 0 warnings/errors |
| `eng/test.ps1` | PASS: 193 ordinary tests; 10 PostgreSQL/full-stack conditional skips |
| M6 dedicated suite | PASS: 31/31 |
| Architecture suite | PASS: 10/10 |
| Azure optional pack build/test | PASS: build + 1/1 test |
| Documentation validation | PASS |
| Conservative secret scan | PASS |
| SBOM generation/validation | PASS, includes `auth-certificate-signing.spdx.json` |
| SBOM mode regression | PASS |
| Vulnerable transitive packages | None reported |
| Core OSS export | PASS: 322 files; manifest SHA-256 `12CAF5606C99419399A5B6EEBA514059A26B276AAFB14DDE019CD95D4E790425` |
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
NO-GO. The documentation publication commit is required to pass the same PR workflows
before hand-off.

## Residual risk

- no real cloud/provider signing or hardware-backed key was qualified;
- no authoritative FVG/Umbria claims, certificate policy, revocation behavior or token
  lifecycle was supplied;
- the Gateway/provider host remains in the TCB and Administrator/SYSTEM remains a
  residual privileged threat;
- an official Connector profile and four-eyes-approved binding are still required before
  any production invocation path exists.
