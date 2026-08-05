# Security policy

## Private reporting

Do not open public issues containing exploitable vulnerabilities, secrets or personal data. Use GitHub Private Vulnerability Reporting / Security Advisories for this repository. The future public contact is currently `SECURITY-CONTACT-PENDING` and must be replaced before publication. Never paste tokens or sensitive evidence into an issue, PR or chat.

## Supported versions and response targets

During private preview only the latest approved `main` baseline is supported. Older baselines receive fixes only when explicitly declared. Maintainers target acknowledgement within three business days and an initial assessment within ten business days; these are operational targets, not contractual SLAs.

## Scope

Relevant findings include Named Pipe/ACL bypass, Installation/PoP authentication, tenant isolation/RLS, grants, SSRF/DNS rebinding, TLS/mTLS, Connector publication/rollback/cache, OIDC/session/CSRF/RBAC/four-eyes, redaction and secret disclosure.

Local Administrator and SYSTEM are not considered fully mitigable threats. The Gateway is part of the trusted computing base and temporarily observes credentials required for outbound calls; it must not persist, log or return them.

Do not attach raw evidence, dumps, EVTX, DPAPI blobs, tokens, private keys, cookies, authorization headers or database exports. Use minimal synthetic and redacted reproductions. If a secret is exposed, revoke/rotate it before sharing any report.
