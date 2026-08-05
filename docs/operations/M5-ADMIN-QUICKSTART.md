# M5 Admin UI local quick start

Prerequisites: Docker Desktop/Linux Engine with Compose, .NET SDK from `global.json`, Node 22 and PowerShell 7 or Windows PowerShell 5.1.

```powershell
git clone https://github.com/marcobiz/secure-integration-platform.git
cd secure-integration-platform
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Validate
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Start
```

Open `https://localhost:18443/admin/` and accept only the per-run synthetic CA in the documented local environment. DevelopmentAuth offers fixed synthetic identities: viewer, editor, approver, operator and security-admin. It is disabled by default outside this Compose overlay and Production refuses to start with it enabled.

Start creates a synthetic Installation and consumes its one-time activation code through the real enrollment challenge and ECDSA proof-of-possession client. The command fails unless PostgreSQL reports the Installation as `Active`; the installation is then visible in the Admin UI inventory. Raw activation material remains only under the ignored `.artifacts` tree and is never printed.

Suggested flow: sign in as editor, import `docs/connectors/examples/sample-secure-service.connector.json`, validate and request approval; sign in as approver and approve/publish; sign in as security-admin to inspect the Active synthetic installation, create another installation if desired, set the complete server-side binding set and create an operation grant; sign in as operator to run the controlled connector test; inspect Audit and Health; publish a second version to exercise rollback and retire.

The browser never receives provider secret values, private keys or arbitrary runtime URLs. PostgreSQL, synthetic provider and mock HTTPS/mTLS service stay on the private Compose network; only Gateway HTTPS is intended for the browser.

Cleanup:

```powershell
./tools/m5/Invoke-M5Quickstart.ps1 -Phase Stop
```

Verify no container or volume remains for Compose project `secure-integration-m5-quickstart`. Raw fixture files under `.artifacts` are ignored and must not be published.
