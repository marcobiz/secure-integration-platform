# ADR-0016: Local Application identification

**Status:** Accepted

## Decision

Combine Windows identity, pipe ACL, Application registration ID, process/PID, canonical path, Authenticode publisher and optional hash. Retain a process handle and creation time to reduce PID reuse/TOCTOU.

## Consequences

The same user does not automatically authorize every process. Publisher/path allow controlled upgrades; hash pinning remains optional because it is fragile. Code injection into the authorized process is a residual risk.

## Rejected alternatives

A process name or a static token in a file is not sufficient identity.
