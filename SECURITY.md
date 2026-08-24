# Security policy

## Private vulnerability reporting

Report a suspected vulnerability privately to [supporto@apocert.it](mailto:supporto@apocert.it). Use a subject that identifies Secure Integration Platform and that the message is a security report. Do not open a public issue for an exploitable vulnerability and never place a secret in an issue, pull request, discussion, or chat.

A useful report contains the affected version or commit, affected component, prerequisites, impact, minimal reproduction steps using synthetic data, and any suggested mitigation. Redact tokens, cookies, authorization headers, private keys, certificate private material, credentials, sensitive payloads, personal data, host identifiers, and raw evidence. Revoke or rotate exposed credentials before reporting them. Do not attach dumps, EVTX, DPAPI blobs, database exports, or reusable certificates.

The support scope is the most recent published technical preview. Older versions are supported only when a release note says so. A technical preview is not production-ready, certified, or covered by an SLA. This policy does not promise acknowledgement, assessment, remediation, disclosure, or publication within a particular time.

Relevant findings include authentication or authorization bypass, Named Pipe or ACL weaknesses, Installation/PoP authentication, tenant/RLS isolation, grant enforcement, SSRF/DNS rebinding, TLS/mTLS, Connector publication/rollback/cache, OIDC/session/CSRF/RBAC/four-eyes controls, redaction, and secret disclosure. Local Administrator and SYSTEM are residual privileged threats and are not claimed to be fully mitigated.

For installation questions, usage questions, or other general support, use the repository's public issue templates only when the content is safe to disclose. The security mailbox is for private security reports, not a promise of general or enterprise support. Conduct reports use the process in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), even though the initial contact address is the same.
