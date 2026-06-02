<#
.SYNOPSIS
    Pure-ADSI Active Directory inventory / audit tool (PowerShell 5.1).

.DESCRIPTION
    Enumerates an Active Directory domain using only System.DirectoryServices
    (ADSI / LDAP) -- no RSAT, no ActiveDirectory module, no Quest cmdlets.
    Produces one CSV per object class, ADExplorer-style, for offline review.

    Object classes captured:
        Users, Groups, Computers, Contacts, Printers,
        OrganizationalUnits, GPOs, GPOLinks, DNSZones

.PARAMETER OutputPath
    Folder to write the CSV files into. Created if missing.
    Defaults to .\ADInventory_<domain>_<timestamp>

.PARAMETER Server
    Optional domain controller / LDAP server (FQDN). Defaults to the DC the
    host is bound to (serverless bind).

.PARAMETER SearchBase
    Optional distinguishedName to scope the search (e.g. an OU). Defaults to
    the domain's defaultNamingContext (whole domain).

.PARAMETER Credential
    Optional PSCredential for cross-domain / explicit-auth scenarios.

.PARAMETER PageSize
    LDAP paged-search size. 1000 is the AD server default ceiling.

.EXAMPLE
    .\Invoke-ADInventory.ps1
    Inventories the current domain to a timestamped folder.

.EXAMPLE
    .\Invoke-ADInventory.ps1 -Server dc01.corp.local -OutputPath C:\Audit -Credential (Get-Credential)

.NOTES
    Runs read-only. Requires only authenticated-user read rights, which every
    domain account has by default. Tested on Windows PowerShell 5.1.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$Server,
    [string]$SearchBase,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$PageSize = 1000
)

#region ----------------------------------------------------------- Infrastructure

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue

# userAccountControl bit flags (subset that matters for auditing)
$UacFlags = [ordered]@{
    SCRIPT                         = 0x00000001
    ACCOUNTDISABLE                 = 0x00000002
    HOMEDIR_REQUIRED               = 0x00000008
    LOCKOUT                        = 0x00000010
    PASSWD_NOTREQD                 = 0x00000020
    PASSWD_CANT_CHANGE             = 0x00000040
    ENCRYPTED_TEXT_PWD_ALLOWED     = 0x00000080
    TEMP_DUPLICATE_ACCOUNT         = 0x00000100
    NORMAL_ACCOUNT                 = 0x00000200
    INTERDOMAIN_TRUST_ACCOUNT      = 0x00000800
    WORKSTATION_TRUST_ACCOUNT      = 0x00001000
    SERVER_TRUST_ACCOUNT           = 0x00002000
    DONT_EXPIRE_PASSWORD           = 0x00010000
    MNS_LOGON_ACCOUNT              = 0x00020000
    SMARTCARD_REQUIRED             = 0x00040000
    TRUSTED_FOR_DELEGATION         = 0x00080000
    NOT_DELEGATED                  = 0x00100000
    USE_DES_KEY_ONLY               = 0x00200000
    DONT_REQ_PREAUTH               = 0x00400000
    PASSWORD_EXPIRED               = 0x00800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000
    PARTIAL_SECRETS_ACCOUNT        = 0x04000000
}

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $color = switch ($Level) { 'WARN' {'Yellow'} 'ERROR' {'Red'} 'OK' {'Green'} default {'Gray'} }
    Write-Host ("[{0}] {1,-5} {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message) -ForegroundColor $color
}

# Build a DirectoryEntry for an arbitrary naming context / path, honoring -Server / -Credential.
function New-DirEntry {
    param([string]$Path)
    $prefix = if ($Server) { "LDAP://$Server/" } else { "LDAP://" }
    $full   = "$prefix$Path"
    if ($Credential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $full, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($full)
    }
}

# Convert a single raw LDAP property value into something CSV-friendly.
function Convert-AdValue {
    param($Value, [string]$Name)

    if ($null -eq $Value) { return $null }

    switch -Regex ($Name) {
        '^objectSid$|^objectSID$' {
            try { return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value } catch { return $null }
        }
        '^objectGUID$' {
            try { return ([guid]([byte[]]$Value)).Guid } catch { return $null }
        }
        # Integer8 / FileTime attributes
        '^(accountExpires|pwdLastSet|lastLogon|lastLogonTimestamp|badPasswordTime|lockoutTime)$' {
            try {
                $i = [int64]$Value
                if ($i -le 0 -or $i -eq 9223372036854775807) { return $null }  # never / not set
                return [DateTime]::FromFileTimeUtc($i).ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
            } catch { return $null }
        }
        default {
            if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
            if ($Value -is [byte[]])   { return ([System.BitConverter]::ToString($Value)) -replace '-','' }
            return $Value
        }
    }
}

# Pull a property from a SearchResult; collapse multi-valued props with a delimiter.
function Get-Prop {
    param($Result, [string]$Name, [string]$Delimiter = ';')
    $props = $Result.Properties
    if (-not $props.Contains($Name)) { return $null }
    $col = $props[$Name]
    if ($col.Count -eq 0) { return $null }
    if ($col.Count -eq 1) { return (Convert-AdValue -Value $col[0] -Name $Name) }
    return (($col | ForEach-Object { Convert-AdValue -Value $_ -Name $Name }) -join $Delimiter)
}

# Sanitize a value (e.g. a zone name) for use as a file name.
function Get-SafeFileName {
    param([string]$Name)
    if (-not $Name) { return 'UNNAMED' }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $re = '[{0}]' -f [regex]::Escape($invalid)
    return ($Name -replace $re, '_').Trim()
}

# Decode userAccountControl into a readable flag list.
function ConvertFrom-Uac {
    param([int]$Uac)
    if (-not $Uac) { return $null }
    $set = foreach ($k in $UacFlags.Keys) { if ($Uac -band $UacFlags[$k]) { $k } }
    return ($set -join ';')
}

# Core paged LDAP search. Returns raw SearchResult objects.
function Invoke-LdapSearch {
    param(
        [string]$SearchRoot,                 # DN of the base
        [string]$Filter,                     # LDAP filter
        [string[]]$Properties,               # attributes to load (empty = all)
        [System.DirectoryServices.SearchScope]$Scope = 'Subtree'
    )
    $root = New-DirEntry -Path $SearchRoot
    $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
    $ds.Filter             = $Filter
    $ds.PageSize           = $PageSize          # enables paging past the 1000-object cap
    $ds.SearchScope        = $Scope
    $ds.SizeLimit          = 0
    $ds.CacheResults       = $false
    $ds.ReferralChasing    = 'All'
    if ($Properties) { $null = $ds.PropertiesToLoad.AddRange($Properties) }
    try {
        $results = $ds.FindAll()
        # Force enumeration into an array so we can dispose the searcher safely.
        return @($results)
    } finally {
        # Dispose can itself throw when the bind failed (missing container); swallow
        # it so the *real* search error propagates instead of a misleading Dispose error.
        try { $ds.Dispose() }   catch {}
        try { $root.Dispose() } catch {}
    }
}

# Run one inventory section: search, project to objects, export CSV.
function Export-Section {
    param(
        [string]$Name,
        [string]$SearchRoot,
        [string]$Filter,
        [string[]]$Properties,
        [scriptblock]$Projection,    # takes a SearchResult, returns a [pscustomobject]
        [System.DirectoryServices.SearchScope]$Scope = 'Subtree'
    )
    Write-Log "Collecting $Name ..."
    $rows = @()
    try {
        $results = Invoke-LdapSearch -SearchRoot $SearchRoot -Filter $Filter -Properties $Properties -Scope $Scope
        foreach ($r in $results) {
            try { $rows += (& $Projection $r) } catch { Write-Log "  skip object: $($_.Exception.Message)" WARN }
        }
    } catch {
        Write-Log "$Name FAILED: $($_.Exception.Message)" ERROR
    }
    $file = Join-Path $OutputPath "$Name.csv"
    if ($rows.Count) {
        $rows | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
        Write-Log ("  {0,-20} {1,6} objects -> {2}" -f $Name, $rows.Count, (Split-Path $file -Leaf)) OK
    } else {
        # Still emit an empty file so the inventory set is complete/explicit.
        '' | Out-File -FilePath $file -Encoding UTF8
        Write-Log "  $Name : 0 objects (empty CSV written)" WARN
    }
    return $rows.Count
}

#endregion

#region ----------------------------------------------------------- Discover the domain

Write-Log "Binding to RootDSE ..."
try {
    $rootDse = New-DirEntry -Path 'RootDSE'
    $defaultNC  = $rootDse.Properties['defaultNamingContext'].Value
    $configNC   = $rootDse.Properties['configurationNamingContext'].Value
    $rootNC     = $rootDse.Properties['rootDomainNamingContext'].Value
    $dnsHost    = $rootDse.Properties['dnsHostName'].Value
    # Every partition this DC hosts (app partitions like *DnsZones included).
    $namingContexts = @($rootDse.Properties['namingContexts'])
    $rootDse.Dispose()
} catch {
    Write-Log "Could not bind to RootDSE. Are you on a domain-joined host / reachable DC? $($_.Exception.Message)" ERROR
    throw
}

if (-not $SearchBase) { $SearchBase = $defaultNC }
$domainFlat = ($defaultNC -replace 'DC=','' -replace ',','.')

Write-Log "Domain      : $domainFlat"
Write-Log "Default NC  : $defaultNC"
Write-Log "Config NC   : $configNC"
Write-Log "Search base : $SearchBase"
Write-Log "Bound DC    : $dnsHost"

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path (Get-Location) ("ADInventory_{0}_{1}" -f $domainFlat, $stamp)
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
Write-Log "Output      : $OutputPath"
Write-Host ''

$summary = [ordered]@{}

#endregion

#region ----------------------------------------------------------- USERS

$summary.Users = Export-Section -Name 'Users' -SearchRoot $SearchBase `
    -Filter '(&(objectCategory=person)(objectClass=user))' `
    -Properties @('sAMAccountName','userPrincipalName','displayName','givenName','sn','cn',
        'description','mail','title','department','company','manager','telephoneNumber','mobile',
        'physicalDeliveryOfficeName','streetAddress','l','st','postalCode','co',
        'distinguishedName','userAccountControl','whenCreated','whenChanged','pwdLastSet',
        'lastLogonTimestamp','accountExpires','memberOf','primaryGroupID','servicePrincipalName',
        'objectSid','objectGUID','employeeID','adminCount') `
    -Projection {
        param($r)
        $uac = [int](Get-Prop $r 'userAccountControl')
        [pscustomobject][ordered]@{
            sAMAccountName    = Get-Prop $r 'sAMAccountName'
            DisplayName       = Get-Prop $r 'displayName'
            UserPrincipalName = Get-Prop $r 'userPrincipalName'
            GivenName         = Get-Prop $r 'givenName'
            Surname           = Get-Prop $r 'sn'
            Description       = Get-Prop $r 'description'
            Email             = Get-Prop $r 'mail'
            Title             = Get-Prop $r 'title'
            Department        = Get-Prop $r 'department'
            Company           = Get-Prop $r 'company'
            Manager           = Get-Prop $r 'manager'
            Office            = Get-Prop $r 'physicalDeliveryOfficeName'
            Phone             = Get-Prop $r 'telephoneNumber'
            Mobile            = Get-Prop $r 'mobile'
            EmployeeID        = Get-Prop $r 'employeeID'
            Enabled           = -not ($uac -band $UacFlags.ACCOUNTDISABLE)
            Locked            = [bool]($uac -band $UacFlags.LOCKOUT)
            PasswordNeverExp  = [bool]($uac -band $UacFlags.DONT_EXPIRE_PASSWORD)
            PasswordNotReqd   = [bool]($uac -band $UacFlags.PASSWD_NOTREQD)
            SmartcardReqd     = [bool]($uac -band $UacFlags.SMARTCARD_REQUIRED)
            TrustedForDeleg   = [bool]($uac -band $UacFlags.TRUSTED_FOR_DELEGATION)
            DontReqPreauth    = [bool]($uac -band $UacFlags.DONT_REQ_PREAUTH)
            AdminCount        = Get-Prop $r 'adminCount'
            UACFlags          = ConvertFrom-Uac $uac
            PwdLastSet        = Get-Prop $r 'pwdLastSet'
            LastLogonTS       = Get-Prop $r 'lastLogonTimestamp'
            AccountExpires    = Get-Prop $r 'accountExpires'
            WhenCreated       = Get-Prop $r 'whenCreated'
            WhenChanged       = Get-Prop $r 'whenChanged'
            SPNs              = Get-Prop $r 'servicePrincipalName'
            MemberOf          = Get-Prop $r 'memberOf'
            PrimaryGroupID    = Get-Prop $r 'primaryGroupID'
            DistinguishedName = Get-Prop $r 'distinguishedName'
            ObjectSID         = Get-Prop $r 'objectSid'
            ObjectGUID        = Get-Prop $r 'objectGUID'
        }
    }

#endregion

#region ----------------------------------------------------------- GROUPS

# groupType: high bit (0x80000000) = security, else distribution. Low bits = scope.
$summary.Groups = Export-Section -Name 'Groups' -SearchRoot $SearchBase `
    -Filter '(objectCategory=group)' `
    -Properties @('sAMAccountName','cn','displayName','description','mail','groupType',
        'distinguishedName','managedBy','member','memberOf','adminCount',
        'whenCreated','whenChanged','objectSid','objectGUID') `
    -Projection {
        param($r)
        $gt = [int64](Get-Prop $r 'groupType')
        $isSecurity = [bool]($gt -band 0x80000000)
        $scope = if ($gt -band 0x00000008) { 'Universal' }
                 elseif ($gt -band 0x00000004) { 'DomainLocal' }
                 elseif ($gt -band 0x00000002) { 'Global' }
                 else { 'BuiltinLocal' }
        $members = Get-Prop $r 'member'
        [pscustomobject][ordered]@{
            sAMAccountName    = Get-Prop $r 'sAMAccountName'
            Name              = Get-Prop $r 'cn'
            DisplayName       = Get-Prop $r 'displayName'
            Description       = Get-Prop $r 'description'
            Email             = Get-Prop $r 'mail'
            Category          = if ($isSecurity) { 'Security' } else { 'Distribution' }
            Scope             = $scope
            MemberCount       = if ($members) { ($members -split ';').Count } else { 0 }
            ManagedBy         = Get-Prop $r 'managedBy'
            AdminCount        = Get-Prop $r 'adminCount'
            WhenCreated       = Get-Prop $r 'whenCreated'
            WhenChanged       = Get-Prop $r 'whenChanged'
            Members           = $members
            MemberOf          = Get-Prop $r 'memberOf'
            DistinguishedName = Get-Prop $r 'distinguishedName'
            ObjectSID         = Get-Prop $r 'objectSid'
            ObjectGUID        = Get-Prop $r 'objectGUID'
        }
    }

#endregion

#region ----------------------------------------------------------- COMPUTERS

$summary.Computers = Export-Section -Name 'Computers' -SearchRoot $SearchBase `
    -Filter '(objectCategory=computer)' `
    -Properties @('name','sAMAccountName','dNSHostName','description','operatingSystem',
        'operatingSystemVersion','operatingSystemServicePack','userAccountControl',
        'distinguishedName','whenCreated','whenChanged','lastLogonTimestamp','pwdLastSet',
        'servicePrincipalName','managedBy','location','objectSid','objectGUID') `
    -Projection {
        param($r)
        $uac = [int](Get-Prop $r 'userAccountControl')
        [pscustomobject][ordered]@{
            Name              = Get-Prop $r 'name'
            sAMAccountName    = Get-Prop $r 'sAMAccountName'
            DNSHostName       = Get-Prop $r 'dNSHostName'
            Description       = Get-Prop $r 'description'
            OperatingSystem   = Get-Prop $r 'operatingSystem'
            OSVersion         = Get-Prop $r 'operatingSystemVersion'
            OSServicePack     = Get-Prop $r 'operatingSystemServicePack'
            Enabled           = -not ($uac -band $UacFlags.ACCOUNTDISABLE)
            TrustedForDeleg   = [bool]($uac -band $UacFlags.TRUSTED_FOR_DELEGATION)
            Location          = Get-Prop $r 'location'
            ManagedBy         = Get-Prop $r 'managedBy'
            PwdLastSet        = Get-Prop $r 'pwdLastSet'
            LastLogonTS       = Get-Prop $r 'lastLogonTimestamp'
            WhenCreated       = Get-Prop $r 'whenCreated'
            WhenChanged       = Get-Prop $r 'whenChanged'
            SPNs              = Get-Prop $r 'servicePrincipalName'
            DistinguishedName = Get-Prop $r 'distinguishedName'
            ObjectSID         = Get-Prop $r 'objectSid'
            ObjectGUID        = Get-Prop $r 'objectGUID'
        }
    }

#endregion

#region ----------------------------------------------------------- CONTACTS

$summary.Contacts = Export-Section -Name 'Contacts' -SearchRoot $SearchBase `
    -Filter '(&(objectClass=contact)(!(objectClass=computer)))' `
    -Properties @('cn','displayName','givenName','sn','mail','description','title',
        'company','department','telephoneNumber','mobile','distinguishedName',
        'whenCreated','whenChanged','objectGUID') `
    -Projection {
        param($r)
        [pscustomobject][ordered]@{
            Name              = Get-Prop $r 'cn'
            DisplayName       = Get-Prop $r 'displayName'
            GivenName         = Get-Prop $r 'givenName'
            Surname           = Get-Prop $r 'sn'
            Email             = Get-Prop $r 'mail'
            Title             = Get-Prop $r 'title'
            Company           = Get-Prop $r 'company'
            Department        = Get-Prop $r 'department'
            Phone             = Get-Prop $r 'telephoneNumber'
            Mobile            = Get-Prop $r 'mobile'
            Description       = Get-Prop $r 'description'
            WhenCreated       = Get-Prop $r 'whenCreated'
            WhenChanged       = Get-Prop $r 'whenChanged'
            DistinguishedName = Get-Prop $r 'distinguishedName'
            ObjectGUID        = Get-Prop $r 'objectGUID'
        }
    }

#endregion

#region ----------------------------------------------------------- PRINTERS

# Published print queues live as printQueue objects under the host computer object.
$summary.Printers = Export-Section -Name 'Printers' -SearchRoot $SearchBase `
    -Filter '(objectCategory=printQueue)' `
    -Properties @('printerName','cn','serverName','shortServerName','uNCName',
        'driverName','portName','location','description','printShareName',
        'printColor','printDuplexSupported','printMediaReady','distinguishedName',
        'whenCreated','whenChanged','objectGUID') `
    -Projection {
        param($r)
        [pscustomobject][ordered]@{
            PrinterName       = Get-Prop $r 'printerName'
            CN                = Get-Prop $r 'cn'
            ServerName        = Get-Prop $r 'serverName'
            ShortServerName   = Get-Prop $r 'shortServerName'
            ShareName         = Get-Prop $r 'printShareName'
            UNCName           = Get-Prop $r 'uNCName'
            Driver            = Get-Prop $r 'driverName'
            Port              = Get-Prop $r 'portName'
            Location          = Get-Prop $r 'location'
            Description       = Get-Prop $r 'description'
            Color             = Get-Prop $r 'printColor'
            Duplex            = Get-Prop $r 'printDuplexSupported'
            WhenCreated       = Get-Prop $r 'whenCreated'
            WhenChanged       = Get-Prop $r 'whenChanged'
            DistinguishedName = Get-Prop $r 'distinguishedName'
            ObjectGUID        = Get-Prop $r 'objectGUID'
        }
    }

#endregion

#region ----------------------------------------------------------- ORGANIZATIONAL UNITS

$summary.OrganizationalUnits = Export-Section -Name 'OrganizationalUnits' -SearchRoot $SearchBase `
    -Filter '(objectCategory=organizationalUnit)' `
    -Properties @('ou','name','description','distinguishedName','managedBy',
        'gPLink','gPOptions','whenCreated','whenChanged','objectGUID') `
    -Projection {
        param($r)
        $dn = Get-Prop $r 'distinguishedName'
        # depth = count of OU= and DC= comps; cheap nesting indicator
        $depth = ([regex]::Matches($dn, '(?i)OU=')).Count
        [pscustomobject][ordered]@{
            Name              = Get-Prop $r 'ou'
            Description       = Get-Prop $r 'description'
            Depth             = $depth
            ManagedBy         = Get-Prop $r 'managedBy'
            BlockInheritance  = ([int](Get-Prop $r 'gPOptions') -eq 1)
            HasGPOLink        = [bool](Get-Prop $r 'gPLink')
            WhenCreated       = Get-Prop $r 'whenCreated'
            WhenChanged       = Get-Prop $r 'whenChanged'
            DistinguishedName = $dn
            ObjectGUID        = Get-Prop $r 'objectGUID'
        }
    }

#endregion

#region ----------------------------------------------------------- GPOs

# Group Policy objects are groupPolicyContainer objects under CN=Policies,CN=System.
$policiesDN = "CN=Policies,CN=System,$defaultNC"
$gpoLookup = @{}   # {GUID(lower)} -> displayName, reused by GPOLinks
$summary.GPOs = Export-Section -Name 'GPOs' -SearchRoot $policiesDN `
    -Filter '(objectClass=groupPolicyContainer)' `
    -Properties @('displayName','cn','gPCFileSysPath','versionNumber','flags',
        'gPCMachineExtensionNames','gPCUserExtensionNames','distinguishedName',
        'whenCreated','whenChanged','objectGUID') `
    -Projection {
        param($r)
        $cn      = Get-Prop $r 'cn'           # the {GUID}
        $display = Get-Prop $r 'displayName'
        if ($cn) { $gpoLookup[$cn.ToLower()] = $display }
        # flags: bit0 = user config disabled, bit1 = computer config disabled
        $flags = [int](Get-Prop $r 'flags')
        [pscustomobject][ordered]@{
            DisplayName       = $display
            GUID              = $cn
            SysvolPath        = Get-Prop $r 'gPCFileSysPath'
            VersionNumber     = Get-Prop $r 'versionNumber'
            UserCfgDisabled   = [bool]($flags -band 1)
            ComputerCfgDisabled = [bool]($flags -band 2)
            MachineExtensions = Get-Prop $r 'gPCMachineExtensionNames'
            UserExtensions    = Get-Prop $r 'gPCUserExtensionNames'
            WhenCreated       = Get-Prop $r 'whenCreated'
            WhenChanged       = Get-Prop $r 'whenChanged'
            DistinguishedName = Get-Prop $r 'distinguishedName'
            ObjectGUID        = Get-Prop $r 'objectGUID'
        }
    }

#endregion

#region ----------------------------------------------------------- GPO LINKS

# gPLink lives on the domain root, every OU, and every site. Parse it into rows.
# Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=..;<opt>][...]
#   opt bit0 = link disabled, opt bit1 = enforced (LinkOpts: 0 norm,1 disabled,2 enforced,3 both)
Write-Log "Collecting GPOLinks ..."
$gpoLinkRows = @()

function Parse-GPLink {
    param([string]$Container, [string]$ContainerType, [string]$GPLink)
    if (-not $GPLink) { return }
    $order = 0
    foreach ($m in [regex]::Matches($GPLink, '\[LDAP://([^;]+);(\d+)\]')) {
        $order++
        $gpoDN  = $m.Groups[1].Value
        $opt    = [int]$m.Groups[2].Value
        $guid   = $null
        if ($gpoDN -match '\{[0-9A-Fa-f\-]+\}') { $guid = $matches[0] }
        $name = if ($guid -and $gpoLookup.ContainsKey($guid.ToLower())) { $gpoLookup[$guid.ToLower()] } else { '(unknown / external)' }
        $script:gpoLinkRows += [pscustomobject][ordered]@{
            ScopeOfMgmt   = $Container
            ScopeType     = $ContainerType
            LinkOrder     = $order
            GPODisplayName= $name
            GPOGuid       = $guid
            Enabled       = -not ($opt -band 1)
            Enforced      = [bool]($opt -band 2)
            GPODN         = $gpoDN
        }
    }
}

try {
    # 1) Domain root
    $rootObj = Invoke-LdapSearch -SearchRoot $defaultNC -Filter '(objectClass=domainDNS)' -Properties @('gPLink','distinguishedName') -Scope Base
    foreach ($o in $rootObj) { Parse-GPLink -Container (Get-Prop $o 'distinguishedName') -ContainerType 'Domain' -GPLink (Get-Prop $o 'gPLink') }

    # 2) OUs
    $ous = Invoke-LdapSearch -SearchRoot $SearchBase -Filter '(&(objectCategory=organizationalUnit)(gPLink=*))' -Properties @('gPLink','distinguishedName')
    foreach ($o in $ous) { Parse-GPLink -Container (Get-Prop $o 'distinguishedName') -ContainerType 'OU' -GPLink (Get-Prop $o 'gPLink') }

    # 3) Sites (configuration partition)
    $sitesDN = "CN=Sites,$configNC"
    $sites = Invoke-LdapSearch -SearchRoot $sitesDN -Filter '(&(objectClass=site)(gPLink=*))' -Properties @('gPLink','distinguishedName')
    foreach ($o in $sites) { Parse-GPLink -Container (Get-Prop $o 'distinguishedName') -ContainerType 'Site' -GPLink (Get-Prop $o 'gPLink') }
} catch {
    Write-Log "GPOLinks partial: $($_.Exception.Message)" WARN
}

$glFile = Join-Path $OutputPath 'GPOLinks.csv'
if ($gpoLinkRows.Count) {
    $gpoLinkRows | Export-Csv -Path $glFile -NoTypeInformation -Encoding UTF8
    Write-Log ("  {0,-20} {1,6} links   -> GPOLinks.csv" -f 'GPOLinks', $gpoLinkRows.Count) OK
} else {
    '' | Out-File $glFile -Encoding UTF8
    Write-Log "  GPOLinks : 0 links" WARN
}
$summary.GPOLinks = $gpoLinkRows.Count

#endregion

#region ----------------------------------------------------------- DNS ZONES

# AD-integrated DNS zones can live in ANY directory partition: each domain's own
# DomainDnsZones partition, the forest-wide ForestDnsZones partition, custom DNS
# application partitions, and the legacy CN=System location in every domain. Rather
# than hardcode paths, discover every partition (from the bound DC's namingContexts
# AND the forest-wide Partitions container) and probe each one for DNS data.
Write-Log "Collecting DNSZones ..."
$dnsRows = @()

# Friendly label for a DNS container DN (e.g. "DomainDnsZones (corp.local)").
function Get-DnsPartitionLabel {
    param([string]$BaseDN)
    if ($BaseDN -match '(?i)CN=System,') {
        $dom = (($BaseDN -replace '(?i).*?CN=System,','') -replace 'DC=','' -replace ',','.')
        return "Legacy-System ($dom)"
    }
    if ($BaseDN -match '(?i)DC=DomainDnsZones,(.+)$') {
        return "DomainDnsZones (" + (($matches[1]) -replace 'DC=','' -replace ',','.') + ")"
    }
    if ($BaseDN -match '(?i)DC=ForestDnsZones,(.+)$') {
        return "ForestDnsZones (" + (($matches[1]) -replace 'DC=','' -replace ',','.') + ")"
    }
    # Custom application partition: strip the zone RDN + MicrosoftDNS to reveal the NC root.
    $nc = $BaseDN -replace '(?i)^.*?CN=MicrosoftDNS,',''
    return "Custom/Other ($nc)"
}

# DNS resource-record type numbers -> names (the common set; others fall back to TYPE<n>).
$DnsTypeNames = @{
    0='ZERO'; 1='A'; 2='NS'; 5='CNAME'; 6='SOA'; 12='PTR'; 13='HINFO'; 15='MX'; 16='TXT';
    17='RP'; 18='AFSDB'; 24='SIG'; 25='KEY'; 28='AAAA'; 29='LOC'; 33='SRV'; 35='NAPTR';
    39='DNAME'; 43='DS'; 46='RRSIG'; 47='NSEC'; 48='DNSKEY'; 50='NSEC3'; 51='NSEC3PARAM';
    52='TLSA'; 257='CAA'; 65281='WINS'; 65282='WINSR'
}

# Read a big-endian unsigned 16/32-bit integer (RR data fields use network byte order).
function Get-BE16 { param([byte[]]$b, [int]$o) return ([int]$b[$o] -shl 8) -bor [int]$b[$o+1] }
function Get-BE32 { param([byte[]]$b, [int]$o)
    return ([uint32]$b[$o] -shl 24) -bor ([uint32]$b[$o+1] -shl 16) -bor ([uint32]$b[$o+2] -shl 8) -bor [uint32]$b[$o+3]
}

# Decode a DNS_COUNT_NAME (cchNameLength byte, label count, then [len][label]..., trailing root 0).
# Next is computed from cchNameLength so it skips the trailing root byte -- critical for SOA,
# which packs two names back to back (primary server + responsible party).
function Read-DnsCountName {
    param([byte[]]$b, [int]$start)
    $cch        = $b[$start]        # byte count of the label data that follows (incl. trailing root)
    $labelCount = $b[$start + 1]
    $pos = $start + 2
    $labels = @()
    for ($i = 0; $i -lt $labelCount; $i++) {
        $l = $b[$pos]; $pos++
        $labels += [System.Text.Encoding]::ASCII.GetString($b, $pos, $l)
        $pos += $l
    }
    return @{ Name = ($labels -join '.'); Next = $start + 2 + $cch }
}

# Parse one binary dnsRecord blob into a flat record object. Returns $null on empty.
function ConvertFrom-DnsRecord {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 24) { return $null }
    $type    = [BitConverter]::ToUInt16($Bytes, 2)       # type/length are little-endian WORDs
    $ttl     = Get-BE32 $Bytes 12                          # TTL is stored big-endian
    $tsHours = [BitConverter]::ToUInt32($Bytes, 20)
    $static  = ($tsHours -eq 0)
    $typeName = if ($DnsTypeNames.ContainsKey([int]$type)) { $DnsTypeNames[[int]$type] } else { "TYPE$type" }
    $o = 24                                                # start of the RR data section
    $data = $null
    try {
        switch ([int]$type) {
            1  { $data = ([System.Net.IPAddress]::new(([byte[]]$Bytes[$o..($o+3)]))).ToString() }      # A
            28 { $data = ([System.Net.IPAddress]::new(([byte[]]$Bytes[$o..($o+15)]))).ToString() }     # AAAA
            { $_ -in 2,5,12,39 } { $data = (Read-DnsCountName $Bytes $o).Name }                         # NS/CNAME/PTR/DNAME
            15 { $pref = Get-BE16 $Bytes $o; $data = "$pref " + (Read-DnsCountName $Bytes ($o+2)).Name } # MX
            33 {                                                                                         # SRV
                $prio = Get-BE16 $Bytes $o; $wt = Get-BE16 $Bytes ($o+2); $port = Get-BE16 $Bytes ($o+4)
                $data = "$prio $wt $port " + (Read-DnsCountName $Bytes ($o+6)).Name
            }
            6  {                                                                                         # SOA
                $serial=Get-BE32 $Bytes $o; $refresh=Get-BE32 $Bytes ($o+4); $retry=Get-BE32 $Bytes ($o+8)
                $expire=Get-BE32 $Bytes ($o+12); $minTtl=Get-BE32 $Bytes ($o+16)
                $primary = Read-DnsCountName $Bytes ($o+20)
                $admin   = Read-DnsCountName $Bytes $primary.Next
                $data = "$($primary.Name) $($admin.Name) serial=$serial refresh=$refresh retry=$retry expire=$expire minTTL=$minTtl"
            }
            16 {                                                                                         # TXT
                $len = $Bytes[$o]; $data = [System.Text.Encoding]::ASCII.GetString($Bytes, $o+1, $len)
            }
            default { $data = ([System.BitConverter]::ToString($Bytes, $o)) -replace '-','' }            # raw hex
        }
    } catch {
        $data = '(parse-error) ' + (([System.BitConverter]::ToString($Bytes, $o)) -replace '-','')
    }
    $ts = if ($static) { 'static' } else {
        ([DateTime]::new(1601,1,1,0,0,0,[DateTimeKind]::Utc)).AddHours([double]$tsHours).ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
    }
    return [pscustomobject]@{ Type = $typeName; TTL = $ttl; Static = $static; Timestamp = $ts; Data = $data }
}

# Extract every record (dnsNode -> dnsRecord values) from one zone into CSV rows.
function Get-DnsZoneRecords {
    param([string]$ZoneDN, [string]$ZoneName)
    $rows = @()
    $nodes = Invoke-LdapSearch -SearchRoot $ZoneDN -Filter '(objectClass=dnsNode)' `
        -Properties @('dc','name','dnsRecord','dNSTombstoned')
    foreach ($n in $nodes) {
        $owner = [string](Get-Prop $n 'dc'); if (-not $owner) { $owner = [string](Get-Prop $n 'name') }
        $fqdn  = if ($owner -eq '@' -or -not $owner) { $ZoneName } else { "$owner.$ZoneName" }
        $tomb  = [string](Get-Prop $n 'dNSTombstoned')
        $recCol = $n.Properties['dnsRecord']
        foreach ($raw in $recCol) {
            $rec = ConvertFrom-DnsRecord -Bytes ([byte[]]$raw)
            if (-not $rec) { continue }
            $rows += [pscustomobject][ordered]@{
                Zone       = $ZoneName
                OwnerName  = $owner
                FQDN       = $fqdn
                RecordType = $rec.Type
                TTL        = $rec.TTL
                Static     = $rec.Static
                Timestamp  = $rec.Timestamp
                Data       = $rec.Data
                Tombstoned = ($tomb -eq 'True')
            }
        }
    }
    return $rows
}

# --- 1. Discover every partition's naming context -----------------------------
$partitionNCs = New-Object System.Collections.Generic.List[string]
# (a) partitions this DC actually hosts / is enlisted in
foreach ($nc in $namingContexts) { if ($nc) { $partitionNCs.Add([string]$nc) } }
# (b) forest-wide list from the Partitions container (reaches other domains' NCs)
try {
    $crossRefs = Invoke-LdapSearch -SearchRoot "CN=Partitions,$configNC" `
        -Filter '(&(objectCategory=crossRef)(nCName=*))' -Properties @('nCName','dnsRoot')
    foreach ($cr in $crossRefs) {
        $nc = [string](Get-Prop $cr 'nCName')
        if ($nc -and -not ($partitionNCs -contains $nc)) { $partitionNCs.Add($nc) }
    }
} catch {
    Write-Log "  Could not read Partitions container (forest-wide discovery limited): $($_.Exception.Message)" WARN
}

# --- 2. Probe each partition's NC ROOT for DNS zones --------------------------
# Bind to the naming-context ROOT (always binds cleanly -- it's a real partition) and
# run an indexed subtree search for dnsZone objects. This finds zones wherever they
# sit in the partition: CN=MicrosoftDNS for app partitions, or the legacy
# CN=MicrosoftDNS,CN=System for the domain partition. Binding straight to a *sub*-
# container instead can fault with 0x8007200A on application partitions even when the
# container and its zones exist -- which is why the earlier approach missed them.
# objectClass is indexed, so this stays fast even against a large domain NC.
$dnsSearchRoots = @($partitionNCs |
    Where-Object { $_ -notmatch '(?i)^CN=Schema,' -and $_ -notmatch '(?i)^CN=Configuration,' } |
    Select-Object -Unique)
Write-Log "  Probing $($dnsSearchRoots.Count) partition(s) for DNS zones."

# Per-zone record CSVs land in a DNS_Zones subfolder; all records also go to one combined file.
$dnsZoneFolder = Join-Path $OutputPath 'DNS_Zones'
if (-not (Test-Path $dnsZoneFolder)) { New-Item -ItemType Directory -Path $dnsZoneFolder -Force | Out-Null }
$allDnsRecords = @()

$seenZoneDN = New-Object System.Collections.Generic.HashSet[string]
foreach ($base in $dnsSearchRoots) {
    try {
        $zones = Invoke-LdapSearch -SearchRoot $base -Filter '(objectClass=dnsZone)' `
            -Properties @('name','distinguishedName','whenCreated','whenChanged','objectGUID')
        $newCount = 0
        foreach ($z in $zones) {
            $dn = [string](Get-Prop $z 'distinguishedName')
            if (-not $seenZoneDN.Add($dn)) { continue }   # same zone reachable via >1 partition path
            $newCount++
            $zoneName  = [string](Get-Prop $z 'name')
            $isReverse = $zoneName -match '(?i)(in-addr|ip6)\.arpa$'
            # Extract this zone's resource records, write a per-zone CSV, and accumulate.
            $zoneRecords = @()
            try { $zoneRecords = @(Get-DnsZoneRecords -ZoneDN $dn -ZoneName $zoneName) }
            catch { Write-Log "    record extract failed for $zoneName : $($_.Exception.Message)" WARN }
            if ($zoneRecords.Count) {
                $zoneFile = Join-Path $dnsZoneFolder (((Get-SafeFileName $zoneName)) + '.csv')
                $zoneRecords | Export-Csv -Path $zoneFile -NoTypeInformation -Encoding UTF8
                $allDnsRecords += $zoneRecords
            }

            $dnsRows += [pscustomobject][ordered]@{
                ZoneName          = $zoneName
                Direction         = if ($isReverse) { 'Reverse' } else { 'Forward' }
                Partition         = (Get-DnsPartitionLabel $dn)   # label from the zone's own DN
                PartitionDN       = $base
                RecordCount       = $zoneRecords.Count
                WhenCreated       = Get-Prop $z 'whenCreated'
                WhenChanged       = Get-Prop $z 'whenChanged'
                DistinguishedName = $dn
                ObjectGUID        = Get-Prop $z 'objectGUID'
            }
        }
        if ($newCount) { Write-Log ("    {0,4} zone(s) in {1}" -f $newCount, $base) OK }
    } catch {
        # Unreachable partitions are expected: app partitions on other domains' DCs this
        # server isn't enlisted in, or referral targets that are down. Stay quiet for those
        # and for empty containers; only surface genuinely unexpected errors.
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        $benign = $msg -match '(?i)no such object|does not exist|attribute or value|unknown error|not operational|referral'
        if (-not $benign) {
            Write-Log "  DNS partition '$base' not searchable: $msg" WARN
        }
    }
}
$dnsFile = Join-Path $OutputPath 'DNSZones.csv'
if ($dnsRows.Count) {
    $dnsRows | Export-Csv -Path $dnsFile -NoTypeInformation -Encoding UTF8
    Write-Log ("  {0,-20} {1,6} zones   -> DNSZones.csv" -f 'DNSZones', $dnsRows.Count) OK
} else {
    '' | Out-File $dnsFile -Encoding UTF8
    Write-Log "  DNSZones : 0 zones (no AD-integrated zones, or no read access)" WARN
}
$summary.DNSZones = $dnsRows.Count

# Combined record file across all zones (per-zone files already written to DNS_Zones\).
$dnsRecFile = Join-Path $OutputPath 'DNSRecords.csv'
if ($allDnsRecords.Count) {
    $allDnsRecords | Export-Csv -Path $dnsRecFile -NoTypeInformation -Encoding UTF8
    Write-Log ("  {0,-20} {1,6} records -> DNSRecords.csv  (+ per-zone CSVs in DNS_Zones\)" -f 'DNSRecords', $allDnsRecords.Count) OK
} else {
    '' | Out-File $dnsRecFile -Encoding UTF8
}
$summary.DNSRecords = $allDnsRecords.Count

#endregion

#region ----------------------------------------------------------- SUMMARY

Write-Host ''
Write-Log "===== Inventory complete =====" OK
$summaryRows = foreach ($k in $summary.Keys) {
    [pscustomobject]@{ Section = $k; Count = $summary[$k] }
}
$summaryRows | Format-Table -AutoSize | Out-Host
$summaryRows | Export-Csv -Path (Join-Path $OutputPath '_Summary.csv') -NoTypeInformation -Encoding UTF8
Write-Log "CSV files written to: $OutputPath" OK

#endregion
