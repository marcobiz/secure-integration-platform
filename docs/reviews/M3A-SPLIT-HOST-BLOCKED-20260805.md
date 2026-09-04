# M3A split-host — Blocked run 2026-08-05

RunId: `m3a-live-20260805-091023`

Candidate commit actually executed in the VM:
`febd8b33201c9827e5e28fcfdd70db1c04d6fce6`.

Result: **BLOCKED — HOST SECURITY DRIVER SCHANNEL INCOMPATIBILITY**.
The run is not an M3A PASS, and none of its activation codes, certificates,
handoff or RunId may be reused.

## Positive evidence obtained before the blocker

The VM path produced consistent original redacted evidence, not a reconstruction:

- Broker installed as a real Windows Service, `Running` state;
- `StartName` `NT SERVICE\SecureIntegrationBroker` and effective service SID;
- Legacy Simulator executed as a standard user with a `Limited` token;
- P02 Legacy → SDK → Named Pipe → Broker Service → Gateway → PostgreSQL 18 →
  synthetic Vault → HTTPS/mTLS vendor mock completed with a sanitized response;
- unauthorized local application denied;
- ungranted operation denied with `gateway_operation_not_granted`;
- no backend endpoint or vendor secret distributed to the VM;
- VM Event Log and canary scan PASS;
- VM cleanup PASS with zero residual synthetic services, tasks and users.

The four original VM evidence files were transferred outside the repository into the
private bundle `m3a-live-20260805-091023-vm-redacted-recovered.zip`, SHA-256
`69432D0BA1FFF34FE551DE64FFA4A8DBFC47270C6E198F499F3B3E19DFC4FC22`.
Per-file hashes were verified on the HOST. The bundle does not replace the final
HOST bundle and does not turn the run into PASS.

## HOST blocker

During `Finalize`, `SecureIntegration.M3.SecurityDriver.exe` exited before the
HOST negative matrix. The `.NET Runtime` 1026 record attests:

`AuthenticationException: Authentication failed because the platform does not support ephemeral keys`.

The cause is loading the synthetic client certificate through
`X509KeyStorageFlags.EphemeralKeySet`. Windows Schannel cannot present that key
as a TLS client credential. N01–N14, HOST correlation, the aggregate
canary scan and the final bundle therefore did not complete. The control wrapper recorded
`M3A_FINALIZE_FAILED` without claiming PASS.

`Finalize` invoked official cleanup in its error path. Subsequent verification
found zero run Docker containers, volumes and networks, absence
of the `M3A-Isolated` adapter and restoration of the three Firewall profiles to their original
disabled state. Existing evidence was not deleted.

## Corrections

Commits `678aa07ca20802d342d00772c019b233869e7639` and
`2dd70e8` correct and verify only the laboratory:

1. SecurityDriver uses `UserKeySet` on Windows, without `PersistKeySet`, and retains
   `EphemeralKeySet` on other systems;
2. VM packaging explicitly accepts the empty suffix required by the success
   archive in Windows PowerShell 5.1;
3. fail-closed static regressions prevent the two defects from returning;
4. a Windows integration test performs a real Schannel mTLS handshake with a
   client certificate imported through `UserKeySet`.

No production Broker or Gateway file is changed. Before a new run,
green CI on the corrective commit, a new RunId/synthetic material and a new
operational window are mandatory. M3B and M4 remain unstarted.
