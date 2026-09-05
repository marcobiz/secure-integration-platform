# Local Broker — Windows x64 evaluation package

Extract the complete archive into a new directory. `package-manifest.json` records
the source commit, version and SHA-256 inventory; the adjacent `.zip.sha256` checks
download integrity. These checksums are **not signatures or publisher authentication**.
Obtain the archive and expected checksum through a trusted channel.

The package includes .NET 10: no Git, .NET SDK/runtime installation, Node, Docker,
Gateway, database or cloud account is required for local protection. Use Windows
PowerShell 5.1. The selected qualification host is Windows 10 Pro 22H2 x64,
19045.6466; qualification results are reported separately. This is an unsigned
alpha evaluation build, not production support for Windows or an MSI installer.

## Once: user identity, then administrator setup

In the ordinary application user's console, obtain the SID (not a password):

```powershell
[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

Give that SID to the administrator. From the extracted package in an **elevated**
Windows PowerShell, set `$applicationSid` to that observed SID, then run:

```powershell
.\Invoke-LocalBroker.ps1 -Command Install -Instance sample -ApplicationUserSid $applicationSid
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
```

Do not substitute the setup administrator's SID unless that is actually the
application account. Setup grants only that exact account and the installed sample
path/hash, with status and `sample` / `text/plain` protection. The service runs as
`NT SERVICE\SecureIntegrationBroker.Local.sample`, not as that account. Start reports
SCM running; the authorized user's next command tests actual application readiness.

## Everyday use: no elevation

In an ordinary console under the registered application account:

```powershell
$sample = "$env:ProgramFiles\SecureIntegration\LocalBroker\sample\sample\SecureIntegration.Samples.LocalBroker.exe"
& $sample status SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample -
& $sample protect SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample .\sample.envelope
& $sample verify SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample .\sample.envelope
```

The sample protects synthetic text and refuses to overwrite an envelope. Verify
decrypts in memory and also checks context/tampering denials. It never prints keys,
plaintext or ciphertext. Keep the envelope for the restart/update checks.
The SDK authenticates SCM/PID/pipe ownership before sending application data.
An unavailable or unauthorized service gives a bounded error, not an automatic retry.

## Administrator lifecycle and update

From the extracted package, elevated:

```powershell
.\Invoke-LocalBroker.ps1 -Command Stop -Instance sample
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
```

Stop can be repeated and supports partial setup with verified ownership. It preserves
service registration, binaries, policy, identity and protected state. Foreign or
uncertain resources and reparse paths are denied, not deleted.

To update, obtain a new build, verify its inventory and extract into a **new** directory.
Run this from that new package, elevated:

```powershell
.\Invoke-LocalBroker.ps1 -Command Update -Instance sample
```

Then run `verify` as the ordinary application user against the original envelope.
Update preserves policy/identity/keys and updates the authorized sample hash; key
initialization is disabled before copying. A failed update reports failure and
preserves state: fix the cause and explicitly repeat Update, never Install or key
initialization as recovery. This is not transactional rollback or a general guarantee
of compatibility across releases; compare the declared source commits, not just
the shared alpha version.

Back up installation metadata, policy, the complete protected data directory and
ciphertext while stopped, retaining ACLs and the Windows/service profile required
by DPAPI. Blobs alone are not portable recovery material. Machine/profile loss can
make data unrecoverable. Administrator/SYSTEM and code injected into an authorized
application remain residual threats. There is no destructive uninstall in this guide.
