# M3 — Redacted evidence schema

The M3 bundle is reproducible evidence, not a raw-data archive. The JSON manifest
uses ordered properties and contains:

- `schemaVersion`, `runId`, `environment` (`M3A`, `M3A-CI` or `M3B`) and `scope`;
- `commitSha`, `m2BaselineTag`, `startedAtUtc`, `completedAtUtc`;
- SHA-256 digests of images and migrations; the bundle digest is in an external sidecar
  to avoid a circular reference;
- public identities (service/account SID or Managed Identity resource ID), never tokens;
- scenario list with ID, status and observed code; duration and evidence files are required
  for the M3A/M3B live gates and optional in the `M3A-CI` sub-gate;
- Vault/mock/DB counters before and after negative paths;
- canary scan result and verified cleanup before finalization;
- tool/runtime versions.

Allowed files: manifest, Markdown report, JUnit/TRX without payloads, public ACL/configuration,
metadata-only audit queries, SBOM, digests and sidecars. Prohibited files: private keys, PFX,
activation codes, API keys, raw bodies, DPAPI blobs, tokens, environment dumps, unredacted EVTX,
core dumps and unredacted logs.

Redaction replaces values with stable identifiers (`[REDACTED:<kind>]`) and then
performs a byte-for-byte search for the eleven original canaries. The bundle is created only
after that search, and its hash is computed over the final immutable bytes.
