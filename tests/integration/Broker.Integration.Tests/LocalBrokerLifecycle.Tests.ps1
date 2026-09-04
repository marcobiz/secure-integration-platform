# Tests the shipped ownership and Stop control flow with a simulated SCM. No service is installed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '..\..\..\deploy\windows\Invoke-LocalBroker.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'SCRIPT_PARSE_FAILED' }
foreach ($functionName in @('Assert-NoReparse', 'Get-OwnedService')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true)
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$stopBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''Stop''' }, $false)
if (-not $stopBranch) { throw 'STOP_CONTROL_FLOW_NOT_FOUND' }
$stop = [ScriptBlock]::Create($stopBranch.Extent.Text)
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('broker-lifecycle-test-' + [guid]::NewGuid().ToString('N'))
$root = Join-Path $fixture 'install'; $data = Join-Path $fixture 'data'; $marker = Join-Path $root 'installation.json'
$name = 'SecureIntegrationBroker.Local.fixture'
$binaryPath = '"' + (Join-Path $root 'broker.exe') + '"'
$script:service = $null; $script:stops = 0
function Get-CimInstance { param($ClassName, $Filter) return $script:service }
function Invoke-ServiceAction { param($Action) if ($Action -cne 'Stop') { throw 'UNEXPECTED_SCM_MUTATION' }; $script:stops++; $script:service.State = 'Stopped' }
function Get-Service { param($Name) return [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value { param($State, $Timeout) if ($State -ne 'Stopped') { throw 'UNEXPECTED_WAIT' } } -PassThru }
function Assert([bool] $Condition) { if (-not $Condition) { throw 'LIFECYCLE_ASSERTION_FAILED' } }
function ExpectDenied { param([scriptblock] $Action) try { & $Action | Out-Null } catch { Assert ($_.Exception.Message -like 'LOCAL_BROKER_*'); return }; throw 'OWNERSHIP_WAS_NOT_DENIED' }
try {
    New-Item -ItemType Directory -Path $root, $data -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $data 'preserve.bin'), 'synthetic fixture marker')
    ExpectDenied { Get-OwnedService }
    $record = @{ service = $name; root = $root; data = $data; binaryPath = $binaryPath }
    [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json))
    $owned = Get-OwnedService; $Command = 'Stop'; & $stop | Out-Null
    Assert ($script:stops -eq 0)
    $script:service = [pscustomobject]@{ PathName = $binaryPath; StartName = 'NT SERVICE\' + $name; State = 'Running' }
    $owned = Get-OwnedService; & $stop | Out-Null
    $owned = Get-OwnedService; & $stop | Out-Null
    Assert ($script:stops -eq 1)
    Assert (Test-Path -LiteralPath (Join-Path $data 'preserve.bin'))
    $script:service.PathName = 'foreign.exe'
    ExpectDenied { Get-OwnedService }
    Assert ($script:stops -eq 1)
    $script:service = $null
    $record.data = Join-Path $fixture 'foreign'
    [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json))
    ExpectDenied { Get-OwnedService }
    Assert (Test-Path -LiteralPath (Join-Path $data 'preserve.bin'))
    Write-Output 'STOP_ABSENT_NORMAL_REPEAT_OWNERSHIP=PASS (simulated SCM)'
}
finally {
    if (([IO.Path]::GetFullPath($fixture)).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
