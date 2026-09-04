# M3A — Split-host product gate closure

Date: 2026-08-05

RunId: `m3a-live-20260805-094131`

Candidate commit: `86b4e0f56d2b1f6f1ee28cc669362177007e896b`

Result: **PASS — M3A PRODUCT GATE**.

The laboratory finalizer remains separately **BLOCKED**. This distinction is
intentional: the gate measures the product properties listed in the Gate Review, not the
harness's ability to independently produce a single formal summary.

## Original evidence

The VM produced an original redacted archive, not a reconstruction:

- `m3a-live-20260805-094131-vm-redacted.zip`;
- SHA-256 `966C9B301B3F6E3E6679B0C00408391E736B9BBCC0808F45EC9C3ED188FA2CAA`;
- internal `RESULT.json` `PASS`, classification `COMPLETED`;
- `vm-manifest.json` `PASS` on the candidate commit;
- VM cleanup `PASS`, zero residual synthetic services, tasks and users.

The manifest demonstrates:

- real Broker `Running` with StartName `NT SERVICE\SecureIntegrationBroker` and service SID;
- standard-user Legacy Simulator, `Limited` token and assigned batch logon;
- P02 Legacy → SDK → Named Pipe → Windows Service → HOST Gateway → PostgreSQL 18 →
  synthetic Vault → HTTPS/mTLS vendor mock `PASS`;
- denied operation grant and denied unauthorized local application;
- vendor secrets and backend endpoints absent from the VM;
- VM Event Log/canary scan `PASS`.

The HOST `SecurityDriver` produced `security-scenarios.json` before cleanup. P01,
P03–P07 and all mandatory N01–N14 scenarios are `PASS`, including revocation, invalid
signature, replay, altered tenant, connector/operation grant, URL/secret reference,
SSRF, redirect, wrong client certificate, unavailable Vault and PostgreSQL.

Deterministic CI `30985805020` on the same commit is entirely green: Windows
build/tests, Gitleaks, Gateway container, PostgreSQL 18 and M3 deterministic container
slice. The complete container canary scan is `PASS-CI`.

## Finalizer blocker

The optional `M3-TLS-SELF-SIGNED-APPLICATION-BOUNDARY` check returned
`TLS-HANDSHAKE-REJECTED` on the Windows HOST: the probe still created its self-signed
key as ephemeral, which Schannel could not present. This is not a product rejection of
the certificate after TLS and does not invalidate P02 or the mandatory scenarios. The fix is in commit
`d0e235e` and is covered by fail-closed source validation and the Schannel integration test.
The run was not repeated.

The operator wrapper had also rejected the empty string used to write the canonical
PASS summary, despite `ValidateVm=PASS` and `Run=PASS`; the fix is `b869a33`.
Both are laboratory defects, not Broker, SDK or Gateway defects.

## Correlated evidence bundle

The original evidence was correlated without alteration in the redacted bundle:

`C:\SecureEvidence\m3a-live-20260805-094131\m3a-live-20260805-094131-product-gate-redacted-evidence.zip`

SHA-256:
`FCDC09ED215949E82D2C0955A930F5C70D964E61B6D9E463E86FC876019CD5AF`.

The sidecar matches. The byte-for-byte scan for known synthetic values finds no
activation codes, API keys, tokens, passwords or HMAC keys. The manifest explicitly declares
`productGateStatus: PASS` and `laboratoryFinalizerStatus: BLOCKED`; it does not present the
finalizer as PASS.

## Cleanup and residual limitation

Verified HOST cleanup: zero run containers, volumes, networks and M3A adapters;
Firewall profiles restored to their original state. VM cleanup attested in the manifest.

The aggregate container-log canary scan for this specific run was not reached
by the finalizer after the optional probe. Redaction is covered by the live VM
canary check and deterministic CI on the same commit. This laboratory evidence limitation
is non-blocking and remains declared in the bundle.

M3A is closed as a product gate. M3B has not started; M3 is not Done, no
M3 tag is created and M4 remains prohibited.
