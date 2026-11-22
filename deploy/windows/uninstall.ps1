# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Remove the bomcensus Windows services and releases.

.DESCRIPTION
Stops and deletes the services, the firewall rules and the install
directory. The agent and scanner state (%ProgramData%\bomcensus\agent and
\scanner: identity key, certificate, trust bundle) and the event log sources
are kept unless -Purge is given, so a later install.ps1 continues with the
same identity.
#>
[CmdletBinding()]
param(
    [switch] $Purge
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$System32 = Join-Path $env:SystemRoot 'System32'
$Sc = Join-Path $System32 'sc.exe'
$Install = Join-Path $env:ProgramFiles 'bomcensus'
$Data = Join-Path $env:ProgramData 'bomcensus'
$Services = @('bomcensus-scanner', 'bomcensus-agent', 'bomcensus-updater')

# Remove a directory tree without following junctions or symbolic links in
# it (Remove-Item -Recurse of Windows PowerShell may follow them).
function Remove-Tree([string] $Path) {
    if (Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue) {
        $ErrorActionPreference = 'Continue'
        Push-Location -LiteralPath $System32
        try {
            & (Join-Path $System32 'cmd.exe') /d /c rmdir /s /q $Path 2>&1 | Out-Null
        } finally {
            Pop-Location
        }
        if (Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue) {
            Write-Warning "could not remove all of $Path"
        }
    }
}

foreach ($s in $Services) {
    if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
        Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
        $out = & $Sc delete $s 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Warning "sc.exe delete ${s}: $($out | Out-String)" }
    }
}
if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
    Get-NetFirewallRule -Group 'bomcensus' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

# The services are stopped, so nothing writes the install directory any more.
Remove-Tree $Install
if ($Purge) {
    Remove-Tree $Data
    foreach ($s in $Services) {
        if ([System.Diagnostics.EventLog]::SourceExists($s)) { Remove-EventLog -Source $s }
    }
    Write-Host 'uninstall.ps1: removed everything including state and event log sources'
} else {
    Remove-Tree (Join-Path $Data 'update-spool')
    Write-Host "uninstall.ps1: kept $Data\agent and $Data\scanner; -Purge removes them"
}
