# ADR-0008: Installation identity and mTLS

**Status:** Accepted

## Decision

The Broker generates a non-exportable ECDSA P-256 CNG key and a ClientAuth certificate per Installation. Enrollment uses a single-use activation code and proof-of-possession. The Gateway registers the SPKI/certificate hash, uses mTLS and additionally requires a signed request envelope.

Certificate lifetime is 90 days, renewal starts 30 days before expiry and overlap is at most 7 days.

## Consequences

The MVP does not require a complex CA; trust is registry-backed. Application-level validation is mandatory behind App Service. Reinstallation generates a new key and requires enrollment.

## Rejected alternatives

A shared API key is prohibited; a shared vendor certificate does not identify an Installation; a full enterprise CA is deferred until needed.
