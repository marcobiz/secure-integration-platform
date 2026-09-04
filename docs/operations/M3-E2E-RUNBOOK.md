# M3 runbook — deterministic M3A and M3B Azure smoke

## Common prerequisites

- clean checkout of the candidate commit, descended from the M2 tag;
- PowerShell 5.1 and 7, .NET SDK pinned by `global.json`;
- no credential files or certificates in Git;
- raw directory under `.artifacts/m3/<run-id>`;
- synchronized clock and controlled outbound HTTPS.

## M3A — split-host laboratory with a VM operator

The HOST uses Docker Linux; the VM exposes Windows Service Control Manager. The elevated
phase is a single reviewed PowerShell script run manually by the operator, not a Codex
runner or generic SYSTEM executor. See `M3A-SPLIT-HOST-RUNBOOK.md`.

1. Run preflight and verify elevation, engine, ports and commit.
2. Generate an exclusively synthetic CA, Gateway/mock certificate and client certificates.
3. Start PostgreSQL 18, the migration runner, synthetic Vault, vendor mock and Gateway.
4. Apply Tenant/Application/Installation/activation/grant seed using a separate tool.
5. Install Broker as `NT SERVICE\\SecureIntegrationBroker` and verify service identity/ACLs.
6. Run the Legacy Simulator under the authorized identity.
7. Run P01–P07 and N01–N15, checking Vault/mock counters and audit.
8. Stop the service/containers, redact logs and search for all canaries.
9. Produce the redacted bundle, manifest and SHA-256 sidecar.
10. Remove the account/service/containers and verify zero remaining tasks/processes.

The run fails if it uses in-process fixtures instead of the service/containers, if an
unauthorized credential gains access, if counters show side effects before authorization,
if any canary appears or if cleanup is incomplete.

## M3B — GitHub Environment `azure-dev`

The Environment must use OIDC (`id-token: write`) and non-secret variables for tenant,
subscription, resource group and location. Azure client secrets are not allowed. A
reviewer approves the dev deployment.

1. Authenticate the Action through a federated credential.
2. Create/update RunId-named dev resources using Bicep.
3. Assign only the necessary Key Vault permissions to the Gateway Managed Identity.
4. Insert synthetic API keys and PFX into Key Vault through the OIDC session.
5. Publish the image identified by the candidate commit digest.
6. Apply migrations using a separate identity/role and start the Gateway.
7. Run enrollment and P01–P07/N01–N15 applicable to cloud.
8. Collect deployment outputs, digests, redacted audit/log queries and results.
9. Search for canaries in Application Insights/Log Analytics as well.
10. Delete synthetic values and ephemeral resources according to dev retention policy.

Managed Identity is the Gateway's only identity toward Key Vault. Broker has no Key Vault
route, token or role. OIDC/Azure tokens are not included in artifacts.

## Evidence and diagnostics

A result is valid only if the manifest records the exact commit, RunId, environment,
service identity, image digests, migration checksums, test IDs, UTC timestamps and hashes
of redacted files. On failure, preserve raw evidence in the protected runner/Azure area,
publish only a redacted `BLOCKED` report and do not create the M3 tag.
