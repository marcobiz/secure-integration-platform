# Legacy migration strategy

## Principle

Do not rewrite a working integration without a concrete benefit. Find where the legacy application reads or uses a secret, replace it with a Local Broker/Gateway capability and preserve the rest of the flow.

## Per-product phases

1. Inventory secrets, certificates, tokens and data keys.
2. Classify Vendor/Tenant/Operator/Session/Local Data Key.
3. Map read, use, logging and persistence points.
4. Characterization tests with synthetic fixtures.
5. Decide local/Gateway/hybrid.
6. Decide Secure Layer/Managed Connector.
7. Define Application manifest and operation grants.
8. Implement the minimal seam.
9. Migrate configuration and local data.
10. Regression and security-negative-path tests.
11. Rotate/revoke compromised secrets.
12. Remove old material and reachable code.
13. Block direct egress/bypass.
14. Pilot, rollback plan and completion evidence.

## Integration Seam Map

Required template:

| Field | Description |
|---|---|
| Product/version | Product and build analyzed. |
| Module/method | Integration point, without copying proprietary code. |
| Source finding | Document, finding ID and certainty level. |
| Secret class | Vendor/Tenant/Operator/Session/Local Data Key. |
| Current source | Config, binary, DB, user input, certificate store or log. |
| Target location | Broker/Vault/memory. |
| Execution | broker/gateway/hybrid. |
| Mode | Secure Layer/Managed Connector. |
| Replacement call | IPC/Connector operation. |
| Behavior test | Fixture and expected interaction. |
| Legacy removal | Files/config/code/egress to remove. |
| Rotation/revocation | Required external action. |
| Residual risk | Risk not eliminated. |
| Rollback | Safe path without restoring a compromised secret. |

## Mode-selection rules

Use Secure Layer when:

- the legacy application correctly constructs SOAP/XML/JSON;
- the change can be limited to credential injection, mTLS, HMAC or token exchange;
- logic is strongly tied to the UI/product;
- this is the first use of the protocol.

Use Managed Connector when:

- the same integration serves multiple products/vendors;
- the protocol changes frequently;
- centralized normalization reduces duplication;
- technical logic can be separated from UI and local hardware.

Use Hybrid when browser/MFA/signing are local and token exchange/calls are central. New untyped handoffs require an ADR.

## Secret migration

### Vendor Secret

1. Prepare a new version in the Vault.
2. Create SecretBinding.
3. Test with a synthetic Connector/test Environment.
4. Migrate the product to the Gateway.
5. Disable direct egress.
6. Revoke the old distributed value.
7. Scan packages, release backups and logs.

### Local Tenant Secret

1. Acquire through an authorized UI/utility without a command line.
2. `PutLocalSecret` and return an opaque reference.
3. Update legacy configuration with the reference, not the value.
4. Remove the original value and temporary backups.
5. Verify ACLs, offline use and deletion.

### Local data keys

- New versioned AES-GCM format.
- Reader supports old and new formats during the migration window.
- Writes only in the new format.
- Batch/lazy re-encryption with checkpoints and backups.
- Authentication failure blocks data use and produces redacted diagnostics.

## Characterization tests

The specification reconstructed from reports/decompilation becomes black-box tests:

- call order;
- sanitized method/path/header names;
- payload format with synthetic values;
- token/session lifetime and handoff;
- error mapping;
- observed retry/idempotency.

Each test retains provenance and certainty level, not decompiled code.

## Rollback

Rollback does not mean restoring already compromised credentials. Allowed options:

- ConnectorVersion rollback while retaining the Gateway;
- application rollback to a build that still uses the Broker;
- operation suspension;
- authorized manual fallback for the external service.

Reactivating hardcoded secrets, trust-all or direct egress is prohibited.

## Finding-resolution criterion

A finding is not closed if:

- the secret remains in the package/config/log;
- old code remains reachable;
- the Application can bypass Broker/Gateway;
- direct egress is still allowed;
- the previous certificate/secret is not revoked;
- tests do not cover negative paths and regression.

## Pilot acceptance pack

- Signed/reviewed Integration Seam Map.
- Behavior/regression/security tests.
- Secret-removal and scanning evidence.
- Rotation/revocation evidence.
- Network/egress evidence.
- Rollback test.
- Residual-risk acceptance.
- Support and incident-response runbook.
