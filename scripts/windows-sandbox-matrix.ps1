# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

#Requires -Version 5.1

<#
.SYNOPSIS
Run the Windows version command sandbox tests under several accounts.

.DESCRIPTION
Builds the test binary of internal/sandbox and bomcensus-probe, then runs
the sandbox tests and "bomcensus-probe self-test" as:

  current  the account running the script (in CI the runner's elevated
           administrator)
  system   LocalSystem, through a scheduled task
  user     a new standard user, through Start-Process -Credential

The real runtimes found on the machine (java, node, python, pwsh) are run
as version commands and logged (TestRunRuntimes). Each scenario must pass;
the self-test must report every version command check as ok.

system and user need an elevated administrator and change the machine (a
scheduled task, a local user, both removed afterwards): run them on a
disposable machine only.

.PARAMETER Scenarios
Scenarios to run (default current, system, user).

.PARAMETER Bin
Working directory for the binaries and logs.

.PARAMETER NoBuild
Use sandbox.test.exe and bomcensus-probe.exe already in Bin (built
elsewhere, for a machine without Go).
#>

param(
    [string[]]$Scenarios = @('current', 'system', 'user'),
    [string]$Bin = (Join-Path $env:ProgramData 'bomcensus-sandbox-test'),
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

function Fail([string]$msg) { throw "windows-sandbox-matrix: $msg" }

$Root = Split-Path -Parent $PSScriptRoot
$Logs = Join-Path $Bin 'logs'
New-Item -ItemType Directory -Force -Path $Bin, $Logs | Out-Null

# The binaries must be readable for AppContainers (as in Program Files) and
# for the test user.
$RX = '(OI)(CI)RX'
& icacls.exe $Bin /grant "*S-1-15-2-1:$RX" "*S-1-15-2-2:$RX" "*S-1-5-32-545:$RX" | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'icacls failed' }

$SandboxTest = Join-Path $Bin 'sandbox.test.exe'
$Probe = Join-Path $Bin 'bomcensus-probe.exe'
if (-not $NoBuild) {
Push-Location $Root
try {
    & go test -c -o $SandboxTest ./internal/sandbox
    if ($LASTEXITCODE -ne 0) { Fail 'go test -c failed' }
    & go build -trimpath -o $Probe ./cmd/bomcensus-probe
    if ($LASTEXITCODE -ne 0) { Fail 'go build failed' }
} finally { Pop-Location }
}

# Runtimes on the machine, as "path|args" entries.
$runtimes = @()
foreach ($r in @(@('java', '-version'), @('node', '--version'), @('python', '--version'), @('pwsh', '-Version'))) {
    $c = Get-Command $r[0] -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { $runtimes += "$($c.Source)|$($r[1])" }
}
$Runtimes = $runtimes -join ';'
Write-Host "runtimes: $Runtimes"

# The command of one scenario, as a batch file that writes the logs and
# the exit codes.
function Write-ScenarioScript([string]$name) {
    $out = Join-Path $Logs "$name.test.log"
    $self = Join-Path $Logs "$name.selftest.json"
    $done = Join-Path $Logs "$name.exit"
    $bat = Join-Path $Bin "$name.cmd"
    @(
        '@echo off'
        "set `"BOMCENSUS_TEST_RUNTIMES=$Runtimes`""
        "`"$SandboxTest`" -test.v -test.count=1 > `"$out`" 2>&1"
        'set T=%ERRORLEVEL%'
        "`"$Probe`" self-test --json > `"$self`" 2>&1"
        "echo %T% > `"$done`""
    ) | Set-Content -Encoding ASCII -Path $bat
    Remove-Item -Force -ErrorAction SilentlyContinue $done
    return $bat, $done
}

function Wait-File([string]$path, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while (-not (Test-Path -LiteralPath $path)) {
        if ((Get-Date) -gt $deadline) { Fail "timed out waiting for $path" }
        Start-Sleep -Seconds 2
    }
}

function Invoke-Current {
    $bat, $done = Write-ScenarioScript 'current'
    & cmd.exe /c $bat
    Wait-File $done 5
}

function Invoke-System {
    $bat, $done = Write-ScenarioScript 'system'
    $task = 'bomcensus-sandbox-test'
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$bat`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $task
        Wait-File $done 900
    } finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }
}

function Invoke-User {
    $bat, $done = Write-ScenarioScript 'user'
    $name = 'bcsbxtest'
    $plain = [Convert]::ToBase64String((1..24 | ForEach-Object { [byte](Get-Random -Maximum 256) })) + 'aA1!'
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    New-LocalUser -Name $name -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
    try {
        Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $name
        & icacls.exe $Logs /grant "${name}:(OI)(CI)M" | Out-Null
        $cred = New-Object System.Management.Automation.PSCredential(".\$name", $secure)
        $p = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$bat`"" -Credential $cred -LoadUserProfile `
            -WorkingDirectory $Bin -WindowStyle Hidden -PassThru
        $p.WaitForExit(900 * 1000) | Out-Null
        Wait-File $done 10
    } finally {
        Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
        Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like "*\$name" } |
            Remove-CimInstance -ErrorAction SilentlyContinue
    }
}

$failed = @()
foreach ($s in $Scenarios) {
    Write-Host "=== scenario $s"
    switch ($s) {
        'current' { Invoke-Current }
        'system' { Invoke-System }
        'user' { Invoke-User }
        default { Fail "unknown scenario $s" }
    }
    $log = Join-Path $Logs "$s.test.log"
    Get-Content -LiteralPath $log | Where-Object { $_ -match '^\s*(---|ok|PASS|FAIL)|winexec_windows_test' } | Write-Host
    $code = [int](Get-Content -LiteralPath (Join-Path $Logs "$s.exit")).Trim()
    if ($code -ne 0) { $failed += "$s tests (exit $code)" }

    # self-test exits 1 for the missing probe sandbox; every version
    # command check must be ok.
    $raw = Get-Content -Raw -LiteralPath (Join-Path $Logs "$s.selftest.json")
    $json = $raw.Substring($raw.IndexOf('{'))
    $json = $json.Substring(0, $json.LastIndexOf('}') + 1)
    $res = $json | ConvertFrom-Json
    foreach ($c in $res.checks) {
        Write-Host ("  {0,-45} {1,-5} {2}" -f $c.name, $c.ok, $c.detail)
        if ($c.name -ne 'sandbox' -and -not $c.ok) { $failed += "$s self-test $($c.name)" }
    }
}
if ($failed.Count -gt 0) { Fail ("failed: " + ($failed -join ', ')) }
Write-Host 'all scenarios passed'
