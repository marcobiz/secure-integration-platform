# M3A split-host — blocked run review 2026-08-04

## Verdict

`m3a-live-20260804-153103` is `BLOCKED — ROLLBACK WINDOW EXPIRED` on
candidate `6c99e566db81aac3700a331a44a807199b06cceb`. It is not M3A evidence,
P02 is not accepted, and neither the RunId nor its activation material may be reused.

The HOST cleanup completed with zero run containers, volumes, networks, listeners,
firewall rules, scheduled rollback tasks, isolated switches, or isolated VM NICs.
The original firewall profile states were restored. Tailscale had been disabled by
the operator and remained stopped. The ephemeral PostgreSQL volume and all raw
activation-code copies were removed without recording the code value.

The authorized VM management audit found no `SecureIntegrationBroker` service,
`M3Legacy04153103` user, per-run scheduled task, or per-run M3Split directory.
`VM-ELEVATED-LAUNCH-STATUS.json` is preserved with failure status. No `RESULT.json`
or complete M3A evidence archive was produced by the expired implementation.

## Findings and corrections

| Finding | Correction | Regression evidence |
|---|---|---|
| Initial collision with the M0/M1 Broker service | M3A invokes the official M0/M1 cleanup only when the service binary is under the exact LiveMatrix installation root and the ownership marker contains a valid owner RunId. Foreign services remain fail-closed. Evidence is never purged. | `M3_split_VM_harness_resolves_only_marker_owned_M0_M1_service_collisions` |
| Legacy account lacked `SeBatchLogonRight` | Grant and verify the right before registering the limited scheduled task; revoke it during owned-account cleanup. | `M3_split_VM_harness_grants_batch_logon_and_install_execute_rights` |
| Protected installation ACL omitted the Legacy Simulator identity | Add inherited `ReadAndExecute` for the exact per-run Legacy SID while retaining protected ACLs and full control only for SYSTEM/Administrators. | `M3_split_VM_harness_grants_batch_logon_and_install_execute_rights` |
| `3.0.0-m3` is not accepted by `System.Version.TryParse` | Send `3.0.0`; M3 remains an environment/test label, not part of the version field. | `M3_split_VM_harness_uses_System_Version_compatible_broker_version` |
| Failure produced neither `RESULT.json` nor a safe evidence archive | Runtime failures now emit a result-only redacted failure archive marked `BLOCKED`; success emits `RESULT.json` marked `PASS`. Partial files are never promoted into the failure archive. | `M3_split_VM_harness_emits_explicit_PASS_or_BLOCKED_result_archives` |

No M3B or M4 activity is authorized by this review. A new live run requires a new
RunId, activation code, certificates, stack, handoff, hash, and rollback window.
