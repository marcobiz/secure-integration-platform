[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $RunId,
    [Parameter(Mandatory)] [string] $BundlePath,
    [Parameter(Mandatory)] [ValidatePattern('^[A-Fa-f0-9]{64}$')] [string] $BundleSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'LiveMatrix.Common.psm1') -Force -DisableNameChecking
$repositoryRoot = Get-LiveMatrixRepositoryRoot
$matrixPath = Join-Path $repositoryRoot 'docs\reviews\M0-M1-REQUIREMENTS-TEST-EVIDENCE.md'
$summaryPath = Join-Path (Get-LiveMatrixPaths -RunId $RunId).Raw 'post-reboot-summary.json'
$summary = Get-Content -Raw -LiteralPath $summaryPath | ConvertFrom-Json
if (-not $summary.passed -or $summary.phase -ne 'post-reboot-complete') { throw 'Requirement evidence can only be updated from a passing post-reboot run.' }

$begin = '<!-- LIVE-MATRIX-AUTOMATION:BEGIN -->'
$end = '<!-- LIVE-MATRIX-AUTOMATION:END -->'
$block = @"
$begin
## Ultima matrice live automatizzata

| Campo | Evidenza |
|---|---|
| Run ID | ``$RunId`` |
| Esito | **PASS live A-F** |
| Macchina/boot | ``$($summary.computerName)`` / ``$($summary.bootTimeUtc)`` |
| Service identity | ``$($summary.service.startName)``; SID ``$($summary.service.processOwnerSid)`` |
| Bundle locale | ``$BundlePath`` |
| SHA-256 bundle | ``$($BundleSha256.ToUpperInvariant())`` |
| Completamento UTC | ``$($summary.completedUtc)`` |

Questa sezione è generata solo dopo una run elevata, un reboot osservato e tutti i fail-closed check superati. Il bundle non è simulato e non è versionato nel repository.
$end
"@
$document = [IO.File]::ReadAllText($matrixPath)
$pattern = [regex]::Escape($begin) + '[\s\S]*?' + [regex]::Escape($end)
if ([regex]::IsMatch($document, $pattern)) { $updated = [regex]::Replace($document, $pattern, $block) }
else { $updated = $document.TrimEnd() + "`r`n`r`n" + $block + "`r`n" }
[IO.File]::WriteAllText($matrixPath, $updated, [Text.UTF8Encoding]::new($false))
