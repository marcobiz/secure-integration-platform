[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
sc.exe stop SecureIntegrationBroker | Out-Null
sc.exe delete SecureIntegrationBroker
if ($LASTEXITCODE -ne 0) { throw "Unable to remove SecureIntegrationBroker service." }
