[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PostgreSqlContainer,

    [ValidateNotNullOrEmpty()]
    [string]$Database = 'broker_gateway_test',

    [ValidateNotNullOrEmpty()]
    [string]$Superuser = 'postgres',

    [ValidateRange(1, 100)]
    [int]$CanonicalIterations = 10,

    [ValidateRange(1, 100)]
    [int]$TargetedIterations = 20,

    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repositoryRoot '.artifacts\postgresql-isolation-qualification.json'
}
elseif (-not [IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $repositoryRoot $OutputPath
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$project = Join-Path $repositoryRoot 'tests\integration\Gateway.Integration.Tests\Gateway.Integration.Tests.csproj'
$migrationProject = Join-Path $repositoryRoot 'src\Gateway\Gateway.Migrations\Gateway.Migrations.csproj'
$temporaryResults = Join-Path ([IO.Path]::GetTempPath()) ('broker-gateway-postgresql-qualification-' + [Guid]::NewGuid().ToString('N'))
$repositoryDotnet = Join-Path $repositoryRoot '.dotnet\dotnet.exe'
$dotnet = if (Test-Path -LiteralPath $repositoryDotnet) { $repositoryDotnet } else { (Get-Command dotnet -ErrorAction Stop).Source }
$docker = (Get-Command docker -ErrorAction Stop).Source
$startedAt = [DateTimeOffset]::UtcNow

foreach ($name in 'GATEWAY_MIGRATION_CONNECTION', 'GATEWAY_POSTGRES_MIGRATION_CONNECTION', 'GATEWAY_POSTGRES_ADMIN_CONNECTION') {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "POSTGRESQL_QUALIFICATION_MISSING_$name"
    }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 wraps native stderr (including harmless psql
        # NOTICE messages) as ErrorRecord objects. The native exit code remains
        # the authoritative fail-closed result.
        $ErrorActionPreference = 'Continue'
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    foreach ($line in $output) { Write-Host $line }
    if ($exitCode -ne 0) {
        throw "POSTGRESQL_QUALIFICATION_NATIVE_FAILURE: $([IO.Path]::GetFileName($FilePath)) exited with $exitCode."
    }
    return ($output -join [Environment]::NewLine)
}

function Assert-UnchangedCommit {
    param([Parameter(Mandatory = $true)][string]$ExpectedCommit)

    $actualCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $ExpectedCommit) {
        throw 'POSTGRESQL_QUALIFICATION_COMMIT_CHANGED'
    }
    $trackedChanges = @(& git -C $repositoryRoot status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $trackedChanges.Count -ne 0) {
        throw 'POSTGRESQL_QUALIFICATION_TRACKED_WORKTREE_NOT_CLEAN'
    }
}

function Invoke-Psql {
    param([Parameter(Mandatory = $true)][string]$Sql)

    return Invoke-NativeChecked -FilePath $docker -Arguments @(
        'exec', $PostgreSqlContainer, 'psql', '-v', 'ON_ERROR_STOP=1',
        '-U', $Superuser, '-d', $Database, '-At', '-c', $Sql)
}

function Read-TrxCounters {
    param([Parameter(Mandatory = $true)][string]$Path)

    [xml]$document = Get-Content -LiteralPath $Path -Raw
    $counters = $document.TestRun.ResultSummary.Counters
    return [ordered]@{
        total = [int]$counters.total
        passed = [int]$counters.passed
        failed = [int]$counters.failed
    }
}

function Invoke-TestIteration {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Iteration,
        [AllowEmptyString()][string]$Filter,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )

    Assert-UnchangedCommit -ExpectedCommit $ExpectedCommit
    $trxName = '{0}-{1:D3}.trx' -f $Name, $Iteration
    $arguments = @(
        'test', $project, '-c', 'Release', '--no-build', '--no-restore',
        '--results-directory', $temporaryResults,
        '--logger', "trx;LogFileName=$trxName")
    if (-not [string]::IsNullOrWhiteSpace($Filter)) {
        $arguments += @('--filter', $Filter)
    }
    Invoke-NativeChecked -FilePath $dotnet -Arguments $arguments | Out-Null
    $counters = Read-TrxCounters -Path (Join-Path $temporaryResults $trxName)
    if ($counters.failed -ne 0 -or $counters.total -ne $counters.passed) {
        throw "POSTGRESQL_QUALIFICATION_TEST_FAILURE_${Name}_$Iteration"
    }
    return $counters
}

function Invoke-TargetedQualification {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Filter,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )

    $passed = 0
    $tests = 0
    for ($iteration = 1; $iteration -le $TargetedIterations; $iteration++) {
        Write-Host "[$Name] iteration $iteration/$TargetedIterations"
        $counters = Invoke-TestIteration -Name $Name -Iteration $iteration -Filter $Filter -ExpectedCommit $ExpectedCommit
        $passed++
        $tests += $counters.total
    }
    return [ordered]@{
        iterations = $TargetedIterations
        passed = $passed
        failed = 0
        testsExecuted = $tests
        filter = $Filter
    }
}

$commit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'POSTGRESQL_QUALIFICATION_GIT_HEAD_FAILED' }
New-Item -ItemType Directory -Path $temporaryResults -Force | Out-Null
New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($OutputPath)) -Force | Out-Null

try {
    Assert-UnchangedCommit -ExpectedCommit $commit
    Invoke-NativeChecked -FilePath $dotnet -Arguments @('restore', $project, '--locked-mode') | Out-Null
    Invoke-NativeChecked -FilePath $dotnet -Arguments @('restore', $migrationProject, '--locked-mode') | Out-Null
    Invoke-NativeChecked -FilePath $dotnet -Arguments @('build', $migrationProject, '-c', 'Release', '--no-restore') | Out-Null
    Invoke-NativeChecked -FilePath $dotnet -Arguments @('build', $project, '-c', 'Release', '--no-restore') | Out-Null

    $postgresqlVersion = (Invoke-Psql -Sql 'SHOW server_version;').Trim()
    if (-not $postgresqlVersion.StartsWith('18.', [StringComparison]::Ordinal)) {
        throw "POSTGRESQL_QUALIFICATION_REQUIRES_VERSION_18: observed $postgresqlVersion"
    }

    $canonicalPassed = 0
    $canonicalTests = 0
    $freshMigrationPassed = 0
    $secondApplyNoOpPassed = 0
    for ($iteration = 1; $iteration -le $CanonicalIterations; $iteration++) {
        Write-Host "[canonical] iteration $iteration/$CanonicalIterations"
        Assert-UnchangedCommit -ExpectedCommit $commit
        Invoke-Psql -Sql 'DROP SCHEMA IF EXISTS gateway CASCADE;' | Out-Null
        $firstApply = Invoke-NativeChecked -FilePath $dotnet -Arguments @('run', '--project', $migrationProject, '-c', 'Release', '--no-build', '--', 'apply')
        if ($firstApply -notmatch '(?m)^Applied ') { throw "POSTGRESQL_QUALIFICATION_FRESH_MIGRATION_FAILED_$iteration" }
        $freshMigrationPassed++
        $secondApply = Invoke-NativeChecked -FilePath $dotnet -Arguments @('run', '--project', $migrationProject, '-c', 'Release', '--no-build', '--', 'apply')
        if ($secondApply -match '(?m)^Applied ') { throw "POSTGRESQL_QUALIFICATION_SECOND_APPLY_NOT_NOOP_$iteration" }
        $secondApplyNoOpPassed++
        if ((Invoke-Psql -Sql "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='gateway' AND c.relrowsecurity AND c.relforcerowsecurity AND c.relname IN ('installation','installation_credential','activation_code','installation_connector_grant','replay_nonce','audit_event','invocation_event');").Trim() -ne '7') {
            throw "POSTGRESQL_QUALIFICATION_FORCE_RLS_FAILED_$iteration"
        }
        Invoke-Psql -Sql "DO `$qualification`$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ci_gateway_admin') THEN CREATE ROLE ci_gateway_admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END `$qualification`$; GRANT gateway_admin TO ci_gateway_admin;" | Out-Null
        $counters = Invoke-TestIteration -Name 'canonical' -Iteration $iteration -Filter '' -ExpectedCommit $commit
        $canonicalPassed++
        $canonicalTests += $counters.total
    }

    $paginationFilter = 'FullyQualifiedName=SecureIntegration.Gateway.Integration.Tests.PostgresIsolationTests.M5_IT_DAT_PostgreSQL18_admin_pagination_has_total_order_and_empty_page_count_when_configured'
    $faultFilter = 'FullyQualifiedName=SecureIntegration.Gateway.Integration.Tests.PostgresIsolationTests.M5_IT_DAT_Fault_injection_rolls_back_admin_state_and_audit_when_configured'
    $tenantConcurrencyFilter = 'FullyQualifiedName=SecureIntegration.Gateway.Integration.Tests.PostgresIsolationTests.M5_IT_DAT_Tenant_mutations_are_FORCE_RLS_correct_atomic_and_concurrent_when_configured'
    $bindingConcurrencyFilter = 'FullyQualifiedName=SecureIntegration.Gateway.Integration.Tests.PostgresIsolationTests.M5_IT_DAT_Approved_binding_digest_and_publication_are_atomic_under_concurrent_mutation_when_configured'

    $pagination = Invoke-TargetedQualification -Name 'pagination' -Filter $paginationFilter -ExpectedCommit $commit
    $bootstrapFaultInjection = Invoke-TargetedQualification -Name 'bootstrap-fault' -Filter $faultFilter -ExpectedCommit $commit
    $tenantApplicationConcurrency = Invoke-TargetedQualification -Name 'tenant-application-concurrency' -Filter $tenantConcurrencyFilter -ExpectedCommit $commit
    $bindingPublicationConcurrency = Invoke-TargetedQualification -Name 'binding-publication-concurrency' -Filter $bindingConcurrencyFilter -ExpectedCommit $commit

    $summary = [ordered]@{
        schemaVersion = 1
        commit = $commit
        startedAtUtc = $startedAt.ToString('o')
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        postgresqlVersion = $postgresqlVersion
        canonical = [ordered]@{
            iterations = $CanonicalIterations
            passed = $canonicalPassed
            failed = 0
            testsExecuted = $canonicalTests
            filter = '<all Gateway.Integration.Tests>'
            freshMigrationPassed = $freshMigrationPassed
            secondApplyNoOpPassed = $secondApplyNoOpPassed
            forcedRlsTables = 7
        }
        pagination = $pagination
        bootstrapFaultInjection = $bootstrapFaultInjection
        tenantApplicationConcurrency = $tenantApplicationConcurrency
        bindingPublicationConcurrency = $bindingPublicationConcurrency
        retryCount = 0
        sleepCount = 0
        globalParallelismDisabled = $false
    }

    $json = $summary | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($OutputPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    $hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText(($OutputPath + '.sha256'), "$hash  $([IO.Path]::GetFileName($OutputPath))$([Environment]::NewLine)", [Text.Encoding]::ASCII)
    [pscustomobject]@{ status = 'PASS'; commit = $commit; evidence = $OutputPath; sha256 = $hash } | ConvertTo-Json -Compress
}
finally {
    Remove-Item -LiteralPath $temporaryResults -Recurse -Force -ErrorAction SilentlyContinue
}
