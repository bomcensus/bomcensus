# Copyright (C) 2026 JC-Lab
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
# Additional terms apply. See LICENSING.md.

#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Install the bomcensus host agent as Windows services.

.DESCRIPTION
Creates the directories with their ACLs, installs a release and registers
the services bomcensus-updater (LocalSystem, no network) and bomcensus-agent
(virtual account NT SERVICE\bomcensus-agent), and optionally
bomcensus-scanner. See docs/DEPLOYMENT.md, chapter "Windows services".

Source is a release bundle (bomcensus-<version>.tar) or a directory with
bomcensus-agent.exe, bomcensus-probe.exe and bomcensus-updater.exe (or with
a windows-<arch> directory holding them). Without Source only directories,
ACLs and services are (re)installed.

A bundle is installed by the updater taken from the bundle, which verifies
it. A directory is copied as it is (no signature check by this script); the
updater adopts it if the binaries pass the Authenticode check.

Running the script again keeps the state and the installed version and
does not enroll again when the agent is enrolled.

.PARAMETER Token
Enrollment string. Defaults to $env:BOMCENSUS_TOKEN, which is preferred:
command lines are visible to other users.

.EXAMPLE
.\install.ps1 .\bomcensus-1.2.0.tar -Server https://bomcensus.example:8443
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Source,
    [string] $Server,
    [string] $Token = $env:BOMCENSUS_TOKEN,
    [ValidateSet('connect', 'listen')]
    [string] $ConnectMode,
    [string] $Listen,
    [string] $ServerName,
    [ValidateSet('pinned', 'system', 'none')]
    [string] $TlsVerify,
    [switch] $Scanner,
    [switch] $NoStart
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$System32 = Join-Path $env:SystemRoot 'System32'
$Sc = Join-Path $System32 'sc.exe'
$Tar = Join-Path $System32 'tar.exe'
$Icacls = Join-Path $System32 'icacls.exe'

$Install = Join-Path $env:ProgramFiles 'bomcensus'
$Data = Join-Path $env:ProgramData 'bomcensus'
$State = Join-Path $Data 'agent'
$Spool = Join-Path $Data 'update-spool'
$ScannerState = Join-Path $Data 'scanner'
$ScannerDir = Join-Path $Install 'scanner'
$AgentFiles = @('bomcensus-agent.exe', 'bomcensus-probe.exe', 'bomcensus-updater.exe')

$SvcUpdater = 'bomcensus-updater'
$SvcAgent = 'bomcensus-agent'
$SvcScanner = 'bomcensus-scanner'
$FirewallGroup = 'bomcensus'

function Fail([string] $Message) {
    throw "install.ps1: $Message"
}

function Info([string] $Message) {
    Write-Host "install.ps1: $Message"
}

# Run a native program quietly and stop on a non-zero exit status. Error
# output of native programs must not turn into terminating errors, so the
# preference is relaxed inside.
function Invoke-Native([string] $Exe, [string[]] $Arguments) {
    $ErrorActionPreference = 'Continue'
    $out = & $Exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "$Exe $($Arguments -join ' ') failed ($LASTEXITCODE): $($out | Out-String)"
    }
}

# Run a bomcensus program with its output shown and return its exit status.
function Invoke-Tool([string] $Exe, [string[]] $Arguments) {
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments | Out-Host
    return $LASTEXITCODE
}

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
    }
}

# SID of the virtual account NT SERVICE\<name>: S-1-5-80 followed by the
# SHA-1 of the upper-case UTF-16LE service name as five 32-bit values. It is
# known before the service exists.
function Get-ServiceSid([string] $Name) {
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try {
        $h = $sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($Name.ToUpperInvariant()))
    } finally {
        $sha.Dispose()
    }
    $parts = for ($i = 0; $i -lt 5; $i++) { [BitConverter]::ToUInt32($h, 4 * $i) }
    'S-1-5-80-' + ($parts -join '-')
}

# Create a directory (refusing a junction or symbolic link planted in its
# place), make Administrators its owner and replace its DACL with Sddl, a
# protected DACL in SDDL form.
function Set-SecureDirectory([string] $Path, [string] $Sddl) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item) {
        if (-not $item.PSIsContainer) { Fail "$Path exists and is not a directory" }
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            Fail "$Path is a junction or symbolic link; remove it and run the script again"
        }
    } else {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
    Invoke-Native $Icacls @($Path, '/setowner', '*S-1-5-32-544', '/q')
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($Sddl, [System.Security.AccessControl.AccessControlSections]::Access)
    [System.IO.Directory]::SetAccessControl($Path, $acl)
}

function Get-Current {
    $cur = Get-Item -LiteralPath (Join-Path $Install 'current') -Force -ErrorAction SilentlyContinue
    if ($cur -and ($cur.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $cur }
    return $null
}

function Stop-BomService([string] $Name) {
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

function New-TempDir {
    $t = Join-Path $Install ('.bootstrap-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 12))
    New-Item -ItemType Directory -Path $t | Out-Null
    return $t
}

function Get-BundleManifest([string] $Bundle, [string] $Tmp) {
    Invoke-Native $Tar @('-x', '-f', $Bundle, '-C', $Tmp, 'manifest.json')
    return Get-Content -Raw -LiteralPath (Join-Path $Tmp 'manifest.json') | ConvertFrom-Json
}

function Install-Bundle([string] $Bundle) {
    $tmp = New-TempDir
    try {
        $m = Get-BundleManifest $Bundle $tmp
        $v = [string] $m.version
        if (-not $v) { Fail "${Bundle}: no version in manifest.json" }
        if ((Test-Path -LiteralPath (Join-Path $Install "versions\$v")) -and (Get-Current)) {
            Info "version $v is already installed"
            if ($Scanner) { Install-ScannerFromBundle $Bundle $m $v $tmp }
            return
        }
        # The updater is taken from the bundle for this first run only. It
        # verifies the bundle, but a modified bundle could carry a modified
        # updater: check where the bundle came from before running this.
        $member = "windows-$Arch/bomcensus-updater.exe"
        Invoke-Native $Tar @('-x', '-f', $Bundle, '-C', $tmp, $member)
        # A private spool: the shared spool is writable by the agent's
        # account, which could have planted links there.
        $priv = Join-Path $tmp 'spool'
        New-Item -ItemType Directory -Path $priv | Out-Null
        Copy-Item -LiteralPath $Bundle -Destination (Join-Path $priv "bomcensus-$v.tar")
        Info "installing $v through the updater"
        $updater = Join-Path $tmp "windows-$Arch\bomcensus-updater.exe"
        if ((Invoke-Tool $updater @('apply', '--spool', $priv, '--install', $Install)) -ne 0) { Fail 'the updater failed' }
        if (-not (Test-Path -LiteralPath (Join-Path $Install "versions\$v")) -or -not (Get-Current)) {
            Fail "the updater did not install $v (see the messages above; a bundle that fails verification is rejected and deleted)"
        }
        if ($Scanner) { Install-ScannerFromBundle $Bundle $m $v $tmp }
    } finally {
        Remove-Tree $tmp
    }
}

# The scanner is not part of an agent installation: the updater verifies it
# with the bundle but does not install it. The manifest of the bundle must be
# the one the updater recorded (manifest_sha256 in state.json) when it
# installed this version, and the scanner must match the manifest.
function Install-ScannerFromBundle([string] $Bundle, $Manifest, [string] $Version, [string] $Tmp) {
    $name = 'bomcensus-scanner.exe'
    $st = Get-Content -Raw -LiteralPath (Join-Path $Install 'state.json') -ErrorAction SilentlyContinue | ConvertFrom-Json
    $recorded = $null
    if ($st -and $st.PSObject.Properties['installed'] -and $st.installed.PSObject.Properties[$Version]) {
        $recorded = $st.installed.$Version.PSObject.Properties['manifest_sha256']
    }
    $have = (Get-FileHash -LiteralPath (Join-Path $Tmp 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $recorded -or $recorded.Value -ne $have) {
        Fail "cannot verify $name of ${Bundle}: version $Version was not installed by the updater from this bundle"
    }
    $entry = @($Manifest.files | Where-Object { $_.os -eq 'windows' -and $_.arch -eq $Arch -and $_.name -eq $name })
    if ($entry.Count -ne 1) { Fail "$Bundle has no windows-$Arch/$name" }
    Invoke-Native $Tar @('-x', '-f', $Bundle, '-C', $Tmp, "windows-$Arch/$name")
    $f = Join-Path $Tmp "windows-$Arch\$name"
    if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry[0].sha256) {
        Fail "$name in $Bundle does not match the manifest"
    }
    Copy-Scanner $f
}

function Copy-Scanner([string] $File) {
    Stop-BomService $SvcScanner
    New-Item -ItemType Directory -Path $ScannerDir -Force | Out-Null
    Copy-Item -LiteralPath $File -Destination (Join-Path $ScannerDir 'bomcensus-scanner.exe') -Force
    Info "scanner installed in $ScannerDir"
}

function Install-Directory([string] $Dir) {
    $sub = Join-Path $Dir "windows-$Arch"
    if (Test-Path -LiteralPath $sub -PathType Container) { $Dir = $sub }
    foreach ($f in $AgentFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $Dir $f) -PathType Leaf)) { Fail "$Dir\$f not found" }
    }
    $v = (& (Join-Path $Dir 'bomcensus-updater.exe') version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $v) { Fail "cannot run $Dir\bomcensus-updater.exe version" }
    $dst = Join-Path $Install "versions\$v"
    if (Test-Path -LiteralPath $dst) {
        Info "version $v is already installed"
    } else {
        Info "copying binaries of version $v (not verified by this script)"
        $versions = Join-Path $Install 'versions'
        New-Item -ItemType Directory -Path $versions -Force | Out-Null
        $t = Join-Path $versions ".tmp-install-$PID"
        Remove-Tree $t
        New-Item -ItemType Directory -Path $t | Out-Null
        foreach ($f in $AgentFiles) { Copy-Item -LiteralPath (Join-Path $Dir $f) -Destination $t }
        Rename-Item -LiteralPath $t -NewName $v
    }
    if (-not (Get-Current)) {
        Info "creating $Install\current -> versions\$v"
        New-Item -ItemType Junction -Path (Join-Path $Install 'current') -Value $dst | Out-Null
    }
    if ($Scanner) {
        $s = Join-Path $Dir 'bomcensus-scanner.exe'
        if (-not (Test-Path -LiteralPath $s -PathType Leaf)) { Fail "$s not found" }
        Copy-Scanner $s
    }
}

# Create or update a service. New-Service takes the command line as one
# string; for an existing service it is changed through Win32_Service,
# because sc.exe needs quotes inside an argument there.
function Set-BomService {
    param(
        [string] $Name, [string] $DisplayName, [string] $Description,
        [string] $CommandLine, [string] $Account, [string] $DependsOn,
        [string] $FailureActions
    )
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        $w = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
        $r = Invoke-CimMethod -InputObject $w -MethodName Change -Arguments @{ PathName = $CommandLine }
        if ($r.ReturnValue -ne 0) { Fail "cannot change service ${Name}: Win32_Service.Change returned $($r.ReturnValue)" }
    } else {
        Info "creating service $Name"
        New-Service -Name $Name -BinaryPathName $CommandLine -DisplayName $DisplayName -StartupType Automatic | Out-Null
    }
    Invoke-Native $Sc @('config', $Name, 'start=', 'auto', 'obj=', $Account, 'DisplayName=', $DisplayName)
    if ($DependsOn) { Invoke-Native $Sc @('config', $Name, 'depend=', $DependsOn) }
    Invoke-Native $Sc @('description', $Name, $Description)
    # The service SID lets ACLs and firewall rules name the service.
    Invoke-Native $Sc @('sidtype', $Name, 'unrestricted')
    # Only the privilege every process needs; the token loses the others.
    Invoke-Native $Sc @('privs', $Name, 'SeChangeNotifyPrivilege')
    Invoke-Native $Sc @('failure', $Name, 'reset=', '86400', 'actions=', $FailureActions)
    # Apply the failure actions also when the service stops with an error
    # status, not only when it crashes.
    Invoke-Native $Sc @('failureflag', $Name, '1')
}

function Quote([string] $s) { '"' + $s + '"' }

# --- Checks ---------------------------------------------------------------

if (-not [Environment]::Is64BitProcess) { Fail 'run this script from 64-bit PowerShell' }
switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $Arch = 'amd64' }
    'ARM64' { $Arch = 'arm64' }
    default { Fail "unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
}
if ($Server -and -not $Token) { Fail '-Server needs -Token (or $env:BOMCENSUS_TOKEN)' }
if ($PSBoundParameters.ContainsKey('Token') -and -not $Server -and $ConnectMode -ne 'listen') { Fail '-Token needs -Server' }
if ($ConnectMode -eq 'listen' -and -not $ServerName) { Fail 'listen mode needs -ServerName' }
foreach ($exe in @($Sc, $Tar, $Icacls)) {
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { Fail "$exe not found (Windows 10 1803 / Server 2019 or later is required)" }
}

# --- 1. Directories -------------------------------------------------------
#   %ProgramFiles%\bomcensus    SYSTEM and Administrators write; Users and
#                               the agent account read and execute
#   %ProgramData%\bomcensus     SYSTEM and Administrators; Users may list it
#     agent\                    SYSTEM, Administrators, the agent account
#     scanner\                  SYSTEM, Administrators, the scanner account
#     update-spool\             SYSTEM, Administrators; the agent account may
#                               create, write and delete files (OW limits the
#                               owner of a file to the same rights)

$AgentSid = Get-ServiceSid $SvcAgent
$ScannerSid = Get-ServiceSid $SvcScanner
$RX = '0x1200a9'
$Modify = '0x1301bf'
$Admin = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

Set-SecureDirectory $Install "D:PAI$Admin(A;OICI;$RX;;;BU)(A;OICI;$RX;;;$AgentSid)(A;OICI;$RX;;;$ScannerSid)"
Set-SecureDirectory $Data "D:PAI$Admin(A;;$RX;;;BU)"
Set-SecureDirectory $State "D:PAI$Admin(A;OICI;FA;;;$AgentSid)"
Set-SecureDirectory $Spool "D:PAI$Admin(A;OICI;$Modify;;;$AgentSid)(A;OICI;$Modify;;;OW)"
if ($Scanner) {
    Set-SecureDirectory $ScannerState "D:PAI$Admin(A;OICI;FA;;;$ScannerSid)"
}

# --- 2. Release -----------------------------------------------------------

if ($Source) {
    $item = Get-Item -LiteralPath $Source -ErrorAction SilentlyContinue
    if (-not $item) { Fail "${Source}: no such file or directory" }
    # Nothing may run the updater or the agent while the release changes.
    Stop-BomService $SvcAgent
    Stop-BomService $SvcUpdater
    if ($item.PSIsContainer) {
        Install-Directory $item.FullName
    } else {
        Install-Bundle $item.FullName
    }
}
if (-not (Get-Current)) { Fail "no release installed: $Install\current is missing; give a bundle or a directory of binaries" }
if ($Scanner -and -not (Test-Path -LiteralPath (Join-Path $ScannerDir 'bomcensus-scanner.exe'))) {
    Fail '-Scanner needs a Source that contains bomcensus-scanner.exe'
}

# --- 3. Event log sources and services -----------------------------------

$sources = @($SvcUpdater, $SvcAgent)
if ($Scanner) { $sources += $SvcScanner }
foreach ($s in $sources) {
    if (-not [System.Diagnostics.EventLog]::SourceExists($s)) {
        New-EventLog -LogName Application -Source $s
    }
}

$cur = Join-Path $Install 'current'
Set-BomService -Name $SvcUpdater -DisplayName 'bomcensus updater' `
    -Description 'Verifies and installs bomcensus releases from the update spool. No network access.' `
    -CommandLine ((Quote "$cur\bomcensus-updater.exe") + ' service --install ' + (Quote $Install) + ' --spool ' + (Quote $Spool)) `
    -Account 'LocalSystem' -FailureActions 'restart/2000/restart/5000/restart/10000'
Set-BomService -Name $SvcAgent -DisplayName 'bomcensus agent' `
    -Description 'bomcensus host agent.' `
    -CommandLine ((Quote "$cur\bomcensus-agent.exe") + ' run --state-dir ' + (Quote $State) + ' --update-spool ' + (Quote $Spool)) `
    -Account "NT SERVICE\$SvcAgent" -DependsOn $SvcUpdater -FailureActions 'restart/5000/restart/30000/restart/60000'
if ($Scanner) {
    Set-BomService -Name $SvcScanner -DisplayName 'bomcensus scanner' `
        -Description 'bomcensus remote scanner.' `
        -CommandLine ((Quote "$ScannerDir\bomcensus-scanner.exe") + ' run --state-dir ' + (Quote $ScannerState)) `
        -Account "NT SERVICE\$SvcScanner" -FailureActions 'restart/5000/restart/30000/restart/60000'
}

# --- 4. Firewall ----------------------------------------------------------
# The updater needs no network: block it in both directions. Block rules
# take precedence over allow rules.

if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) {
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($dir in @('Outbound', 'Inbound')) {
        New-NetFirewallRule -Group $FirewallGroup -DisplayName "bomcensus updater: block $dir" `
            -Direction $dir -Action Block -Service $SvcUpdater -Profile Any | Out-Null
    }
    if ($ConnectMode -eq 'listen') {
        $port = '7443'
        if ($Listen -match ':(\d+)$') { $port = $Matches[1] }
        New-NetFirewallRule -Group $FirewallGroup -DisplayName "bomcensus agent: listen mode (TCP $port)" `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Service $SvcAgent -Profile Any | Out-Null
    }
} else {
    Write-Warning 'NetSecurity module not available: the updater is not blocked from the network by a firewall rule'
}

# --- 5. Enrollment --------------------------------------------------------

$enrolled = Test-Path -LiteralPath (Join-Path $State 'enrollment.json')
if ($Server -or $ConnectMode -eq 'listen') {
    if ($enrolled) {
        Info "already enrolled ($State\enrollment.json); not enrolling again"
    } else {
        if (-not $Token) { Fail 'listen mode needs -Token (or $env:BOMCENSUS_TOKEN)' }
        $a = @('enroll', '--state-dir', $State)
        if ($Server) { $a += @('--server', $Server) }
        if ($ConnectMode) { $a += @('--connect-mode', $ConnectMode) }
        if ($Listen) { $a += @('--listen', $Listen) }
        if ($ServerName) { $a += @('--server-name', $ServerName) }
        if ($TlsVerify) { $a += @('--tls-verify', $TlsVerify) }
        Info 'enrolling'
        $saved = $env:BOMCENSUS_TOKEN
        $env:BOMCENSUS_TOKEN = $Token
        try {
            if ((Invoke-Tool (Join-Path $cur 'bomcensus-agent.exe') $a) -ne 0) { Fail 'enrollment failed' }
        } finally {
            $env:BOMCENSUS_TOKEN = $saved
        }
        $enrolled = $true
    }
}

# --- 6. Start -------------------------------------------------------------

if (-not $NoStart) {
    Start-Service -Name $SvcUpdater
    if ($enrolled) {
        Restart-Service -Name $SvcAgent
        Info 'agent started'
    } else {
        Info "not enrolled: the agent service is installed but not started; run '$cur\bomcensus-agent.exe enroll --state-dir $State ...' as Administrator, then 'Start-Service $SvcAgent'"
    }
    if ($Scanner) {
        if (Test-Path -LiteralPath (Join-Path $ScannerState 'enrollment.json')) {
            Restart-Service -Name $SvcScanner
            Info 'scanner started'
        } else {
            Info "scanner not enrolled: run '$ScannerDir\bomcensus-scanner.exe enroll --state-dir $ScannerState ...' as Administrator, then 'Start-Service $SvcScanner'"
        }
    }
}
Info 'done'
