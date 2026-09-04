# ADR-0009: Plugin model

**Status:** Accepted

## Decision

Compiled, in-process .NET plugins, loaded only at startup and distributed by the pipeline. Manifest, SHA-256 hash, CMS signature, publisher allowlist and declared compatibility. No uploads through the UI.

## Consequences

Implementation and operations remain simple, but a malicious plugin is equivalent to a compromised Gateway. The contract supplies restricted services without promising a sandbox. An isolated worker will only be considered for real third-party use cases.

## Rejected alternatives

Scripts, assemblies uploaded through the UI and hot-loading are prohibited; mandatory process isolation in the MVP would add cost without a demonstrated requirement.
