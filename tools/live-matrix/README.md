# M0/M1 live matrix harness

Questo pacchetto esegue la matrice live A-F su una **VM Windows x64 pulita**, con Windows PowerShell elevato. Non contiene fallback simulati: se non può creare account, servizio, token, ACL, reboot o Event Log reali, termina con exit code non zero.

Entry point:

```powershell
.\tools\live-matrix\Invoke-LiveMatrix.ps1 -Phase All -RunId 'm0-m1-YYYYMMDD-01' -Reboot
```

La fase pre-reboot registra un task `SYSTEM`, poi riavvia la VM. Il task esegue la fase post-reboot, crea il bundle redatto sotto `%ProgramData%\SecureIntegration\LiveMatrix\<RunId>\evidence` e aggiorna la sezione generata di `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md` soltanto dopo il PASS completo.

## Componenti

| File | Responsabilità |
|---|---|
| `Invoke-LiveMatrix.ps1` | orchestrazione idempotente e ripresa post-reboot |
| `Test-Prerequisites.ps1` | elevazione, VM, OS/NTFS, SDK e collisioni SCM |
| `Install-LiveBroker.ps1` | build/publish, account locali, policy, servizio e virtual identity |
| `Invoke-PreReboot.ps1` | matrici A-D, restart, tamper, ACL e DPAPI cross-identity |
| `Invoke-PostReboot.ps1` | persistenza E, Event Log/redaction F e chiusura A-F |
| `New-EvidenceBundle.ps1` | allowlist degli artefatti, manifest per-file, ZIP e SHA-256 |
| `Update-RequirementEvidence.ps1` | aggiornamento documentale solo da summary PASS post-reboot |
| `Remove-LiveMatrix.ps1` | cleanup esplicito degli oggetti posseduti dall'harness |
| `probe/` | client reale copiato in path autorizzato/non autorizzato e avviato con token distinti |

Credenziali e canary sintetici restano nello state directory protetto da ACL; sono esclusi dal bundle. I probe sono avviati mediante Task Scheduler con logon reale dei due account locali. L'account autorizzato rappresenta il gestionale/legacy simulator; una copia dello stesso apphost in un path diverso rappresenta il processo non autorizzato sotto lo stesso SID.

Il runbook operativo completo è in `docs/operations/M0-M1-LIVE-MATRIX-RUNBOOK.md`.
