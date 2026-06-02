<#
.SYNOPSIS
    Back up every GPO and (optionally) the entire SYSVOL share -- PowerShell 5.1,
    pure ADSI + robocopy, no RSAT/GroupPolicy module required.

.DESCRIPTION
    For each Group Policy Object in the domain this captures BOTH halves of a GPO:
      1. The SYSVOL file tree  (\\domain\SYSVOL\<domain>\Policies\{GUID})
      2. The AD groupPolicyContainer attributes (versionNumber, flags, CSE GUIDs, ...)
    plus a Manifest.csv mapping every {GUID} -> friendly display name (so the raw
    folders are identifiable later).

    Optionally (-SysvolFull) robocopies the whole SYSVOL share -- Policies AND the
    scripts/NETLOGON tree (logon scripts, etc.).

    If RSAT GPMC is installed, -UseGPMC additionally produces a *native* GPMC backup
    (the kind Restore-GPO / "Manage Backups" can restore) via the GPMgmt.GPM COM API.

.PARAMETER OutputPath
    Destination root. Defaults to .\ADBackup_<domain>_<timestamp>

.PARAMETER Server      Optional DC/LDAP server FQDN (serverless bind if omitted).
.PARAMETER Credential  Optional PSCredential.
.PARAMETER SysvolFull  Also copy the entire SYSVOL share (scripts/NETLOGON included).
.PARAMETER IncludeAcls Copy NTFS owner/ACL info too (robocopy /COPYALL). Needs backup rights.
.PARAMETER UseGPMC     Also create a native, restorable GPMC backup if GPMC is present.

.EXAMPLE
    .\Backup-GPOAndSysvol.ps1
.EXAMPLE
    .\Backup-GPOAndSysvol.ps1 -SysvolFull -UseGPMC -OutputPath D:\ADBackups
.NOTES
    Intended to run on a DOMAIN-JOINED machine, where \\domain\SYSVOL and gPCFileSysPath
    resolve natively. If a SYSVOL path can't be reached it is logged and recorded in the
    manifest (SysvolCopied = False) -- the script does not attempt to work around it.
    Read-only against AD. Copying ACLs (-IncludeAcls / /COPYALL) may need the
    SeBackupPrivilege -- run elevated if you hit access-denied on a few files.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SysvolFull,
    [switch]$IncludeAcls,
    [switch]$UseGPMC
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $c = switch ($Level) { 'WARN' {'Yellow'} 'ERROR' {'Red'} 'OK' {'Green'} default {'Gray'} }
    Write-Host ("[{0}] {1,-5} {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message) -ForegroundColor $c
}

function New-DirEntry {
    param([string]$Path)
    $prefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }
    if ($Credential) {
        New-Object System.DirectoryServices.DirectoryEntry("$prefix$Path",
            $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        New-Object System.DirectoryServices.DirectoryEntry("$prefix$Path")
    }
}

function Get-Prop {
    param($Result, [string]$Name)
    $p = $Result.Properties
    if ($p.Contains($Name) -and $p[$Name].Count) {
        if ($p[$Name].Count -eq 1) { return $p[$Name][0] }
        return @($p[$Name])
    }
    return $null
}

# Strip characters illegal in a Windows file/folder name.
function Get-SafeName {
    param([string]$Name)
    if (-not $Name) { return 'UNNAMED' }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $re = '[{0}]' -f [regex]::Escape($invalid)
    return ($Name -replace $re, '_').Trim()
}

# Robocopy wrapper. Returns $true on success (exit code < 8).
function Invoke-Robocopy {
    param([string]$Source, [string]$Dest, [string]$LogFile)
    $copyFlags = if ($IncludeAcls) { '/COPYALL' } else { '/COPY:DAT' }
    $args = @($Source, $Dest, '/E', $copyFlags, '/R:1', '/W:1', '/XJ',
              '/NP', '/NFL', '/NDL', '/TEE', "/LOG+:$LogFile")
    & robocopy.exe @args | Out-Null
    $code = $LASTEXITCODE
    # robocopy: 0-7 = success (8+ = failure). 0=nothing copied, 1=files copied, etc.
    return ($code -lt 8)
}

#region --- Discover domain / SYSVOL ---

Write-Log "Binding to RootDSE ..."
$rootDse   = New-DirEntry -Path 'RootDSE'
$defaultNC = $rootDse.Properties['defaultNamingContext'].Value
$dnsHost   = $rootDse.Properties['dnsHostName'].Value
$rootDse.Dispose()

$domainDns  = ($defaultNC -replace 'DC=','' -replace ',','.')
# On a domain-joined machine the domain DFS path resolves natively to a nearby DC.
$sysvolRoot = "\\$domainDns\SYSVOL"

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path (Get-Location) ("ADBackup_{0}_{1}" -f $domainDns, $stamp)
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$logFile = Join-Path $OutputPath 'robocopy.log'

Write-Log "Domain       : $domainDns"
Write-Log "SYSVOL src   : $sysvolRoot"
Write-Log "Output       : $OutputPath"
Write-Host ''

#endregion

#region --- Enumerate GPOs from AD ---

Write-Log "Enumerating GPOs from AD ..."
$policiesDN = "CN=Policies,CN=System,$defaultNC"
$root = New-DirEntry -Path $policiesDN
$ds = New-Object System.DirectoryServices.DirectorySearcher($root)
$ds.Filter   = '(objectClass=groupPolicyContainer)'
$ds.PageSize = 1000
$null = $ds.PropertiesToLoad.AddRange(@('displayName','cn','gPCFileSysPath','versionNumber',
    'flags','gPCMachineExtensionNames','gPCUserExtensionNames','gPCFunctionalityVersion',
    'whenCreated','whenChanged','distinguishedName'))
$gpos = @($ds.FindAll())
$ds.Dispose(); $root.Dispose()
Write-Log "Found $($gpos.Count) GPO(s)." OK

#endregion

#region --- Raw per-GPO backup (SYSVOL folder + AD attributes) ---

$gpoBackupRoot = Join-Path $OutputPath 'GPO_Backups'
New-Item -ItemType Directory -Path $gpoBackupRoot -Force | Out-Null

$manifest = @()
$ok = 0; $fail = 0
foreach ($g in $gpos) {
    $guid    = [string](Get-Prop $g 'cn')              # {GUID}
    $name    = [string](Get-Prop $g 'displayName')
    $sysPath = [string](Get-Prop $g 'gPCFileSysPath')  # \\domain\SysVol\domain\Policies\{GUID}
    $safe    = Get-SafeName $name
    $dest    = Join-Path $gpoBackupRoot ("{0}__{1}" -f $guid, $safe)
    $destSv  = Join-Path $dest 'DomainSysvol'
    New-Item -ItemType Directory -Path $destSv -Force | Out-Null

    # 1) AD half -> re-importable XML
    [pscustomobject][ordered]@{
        DisplayName          = $name
        GUID                 = $guid
        DistinguishedName    = [string](Get-Prop $g 'distinguishedName')
        VersionNumber        = [string](Get-Prop $g 'versionNumber')
        Flags                = [string](Get-Prop $g 'flags')
        FunctionalityVersion = [string](Get-Prop $g 'gPCFunctionalityVersion')
        MachineExtensions    = (Get-Prop $g 'gPCMachineExtensionNames') -join ''
        UserExtensions       = (Get-Prop $g 'gPCUserExtensionNames') -join ''
        SysvolPath           = $sysPath
        WhenCreated          = (Get-Prop $g 'whenCreated')
        WhenChanged          = (Get-Prop $g 'whenChanged')
    } | Export-Clixml -Path (Join-Path $dest 'AdBackup.xml')

    # 2) SYSVOL half -> robocopy the policy file tree. On a domain-joined host the
    #    AD-returned gPCFileSysPath (\\domain\SysVol\...) resolves natively. If it can't
    #    be reached, just log it and move on -- no workaround attempted.
    $copied = $false
    $issue  = $null
    if (-not $sysPath) {
        $issue = 'gPCFileSysPath attribute empty'
    } elseif (-not (Test-Path $sysPath)) {
        $issue = "SYSVOL path unreachable: $sysPath"
    } elseif (-not (Invoke-Robocopy -Source $sysPath -Dest $destSv -LogFile $logFile)) {
        $issue = "robocopy reported errors (see robocopy.log): $sysPath"
    } else {
        $copied = $true
    }
    if ($copied) { $ok++ } else { $fail++; Write-Log "  $name -- $issue" WARN }

    $manifest += [pscustomobject]@{
        DisplayName = $name; GUID = $guid; SysvolCopied = $copied
        Issue = $issue; BackupFolder = (Split-Path $dest -Leaf)
    }
    Write-Log ("  {0,-45} {1}" -f $name, $(if ($copied){'OK'}else{'NO SYSVOL (logged)'})) $(if($copied){'OK'}else{'WARN'})
}
$manifest | Export-Csv (Join-Path $OutputPath 'Manifest.csv') -NoTypeInformation -Encoding UTF8
Write-Log "Raw GPO backup: $ok ok, $fail without SYSVOL data." OK

#endregion

#region --- Full SYSVOL copy (optional) ---

if ($SysvolFull) {
    Write-Host ''
    Write-Log "Copying full SYSVOL share (this can take a while) ..."
    $svDest = Join-Path $OutputPath 'SYSVOL_full'
    New-Item -ItemType Directory -Path $svDest -Force | Out-Null
    if (Invoke-Robocopy -Source $sysvolRoot -Dest $svDest -LogFile $logFile) {
        Write-Log "Full SYSVOL copied -> $svDest" OK
    } else {
        Write-Log "Full SYSVOL copy reported errors (see robocopy.log)" WARN
    }
}

#endregion

#region --- Native GPMC backup (optional, restorable) ---

if ($UseGPMC) {
    Write-Host ''
    Write-Log "Attempting native GPMC backup via COM ..."
    try {
        $gpm = New-Object -ComObject GPMgmt.GPM
        $k   = $gpm.GetConstants()
        $dom = $gpm.GetDomain($domainDns, '', $k.UseAnyDC)
        $nativeRoot = Join-Path $OutputPath 'GPMC_Native'
        New-Item -ItemType Directory -Path $nativeRoot -Force | Out-Null
        $all = $dom.SearchGPOs($gpm.CreateSearchCriteria())
        $n = 0
        foreach ($gpo in $all) {
            $res = $gpo.Backup($nativeRoot, "Inventory backup $(Get-Date -Format s)")
            if ($res) { $n++ }
        }
        Write-Log "Native GPMC backup complete: $n GPO(s) -> $nativeRoot (restorable via Restore-GPO)" OK
    } catch {
        Write-Log "GPMC COM not available -- skipping native backup. (RSAT GPMC not installed?) $($_.Exception.Message)" WARN
    }
}

#endregion

Write-Host ''
Write-Log "===== Backup complete =====" OK
Write-Log "Location: $OutputPath" OK
Write-Log "  GPO_Backups\   raw per-GPO (SYSVOL files + AdBackup.xml)"
Write-Log "  Manifest.csv   {GUID} -> display-name index"
if ($SysvolFull) { Write-Log "  SYSVOL_full\   complete SYSVOL share copy" }
if ($UseGPMC)    { Write-Log "  GPMC_Native\   restorable GPMC backups (if GPMC present)" }
Write-Log "  robocopy.log   copy detail / any errors"
