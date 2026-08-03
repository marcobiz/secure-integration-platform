[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ExecutablePath
)

$ErrorActionPreference = 'Stop'
$resolvedExecutable = (Resolve-Path -LiteralPath $ExecutablePath).Path
sc.exe create SecureIntegrationBroker binPath= ('"' + $resolvedExecutable + '"') start= auto obj= 'NT SERVICE\SecureIntegrationBroker'
if ($LASTEXITCODE -ne 0) { throw "Unable to create SecureIntegrationBroker service." }
sc.exe failure SecureIntegrationBroker reset= 86400 actions= restart/5000/restart/15000/none/0
if ($LASTEXITCODE -ne 0) { throw "Unable to configure SecureIntegrationBroker recovery." }
