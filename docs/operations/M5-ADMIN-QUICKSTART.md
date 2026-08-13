# M5 Admin UI local quick start

Prerequisites: Docker Desktop/Linux Engine with Compose, .NET SDK from `global.json`, Node 22 and PowerShell 7 or Windows PowerShell 5.1.

```powershell
git clone https://github.com/marcobiz/secure-integration-platform.git
cd secure-integration-platform
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Validate
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Workflow
```

Open `https://localhost:18443/admin/` and accept only the per-run synthetic CA in the documented local environment. DevelopmentAuth offers fixed synthetic identities: viewer, editor, approver, operator and security-admin. It is disabled by default outside this Compose overlay and Production refuses to start with it enabled.

`Workflow` starts the production-build stack and then runs the deterministic browser/runtime gate. It imports a dedicated `2.0.0` Draft, validates it, creates its complete binding revision, requests approval, proves self-approval is denied, approves as a distinct principal, publishes, grants the already enrolled synthetic installation, invokes that exact published version through authenticated mTLS/PoP runtime, verifies the sanitized vendor response and correlated audit, retires the version, and proves a subsequent invocation is denied. The pre-provisioned `1.0.0` sample therefore cannot short-circuit the documented workflow.

`Start` remains available only when an operator wants to inspect the UI manually. It creates a synthetic Installation and consumes its one-time activation code through the real enrollment challenge and ECDSA proof-of-possession client. Raw activation material remains only under the ignored `.artifacts` tree and is never printed.

Suggested flow: sign in as editor, import `docs/connectors/examples/sample-secure-service.connector.json`, validate and request approval; sign in as approver and approve/publish; sign in as security-admin to inspect the Active synthetic installation, create another installation if desired, set the complete server-side binding set and create an operation grant; sign in as operator to run the controlled connector test; inspect Audit and Health; publish a second version to exercise rollback and retire.

The browser never receives provider secret values, private keys or arbitrary runtime URLs. PostgreSQL, synthetic provider and mock HTTPS/mTLS service stay on the private Compose network; only Gateway HTTPS is intended for the browser.

Cleanup:

```powershell
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Stop
```

Verify no container or volume remains for Compose project `secure-integration-m5-quickstart`. Raw fixture files under `.artifacts` are ignored and must not be published.
`Stop` also removes the marker-owned per-run quickstart directory, including activation
material, synthetic private keys and PFX files. It refuses to recursively remove an
unmarked artifact directory.
