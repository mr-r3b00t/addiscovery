<#
.SYNOPSIS
    Dump the entire LDAP directory to JSON (ADExplorer-style snapshot) -- PowerShell 5.1,
    pure ADSI, no RSAT / ActiveDirectory module.

.DESCRIPTION
    Walks every object in one or more directory partitions and writes ALL readable
    attributes per object to JSON. Default output is JSON Lines (NDJSON): one self-
    contained JSON object per line. NDJSON is the database-import format -- it streams,
    never builds a giant in-memory array, and loads directly into MongoDB
    (mongoimport), Elasticsearch (_bulk), DuckDB (read_json_auto), pandas, or jq.

    Binary attributes are made usable: objectSid / sIDHistory -> SDDL SID string,
    objectGUID -> GUID string, everything else binary -> base64. Dates -> ISO-8601.

.PARAMETER OutputPath   Folder for the dump files. Defaults to .\LdapDump_<domain>_<timestamp>
.PARAMETER Server       Optional DC/LDAP server FQDN (serverless bind if omitted).
.PARAMETER Credential   Optional PSCredential.
.PARAMETER SearchBase   Dump only this DN (subtree). Overrides -AllPartitions.
.PARAMETER AllPartitions Dump every naming context the DC hosts (domain, config,
                        schema, and app partitions like DomainDnsZones). Default is
                        the domain partition only.
.PARAMETER Filter       LDAP filter. Default '(objectClass=*)' = everything.
.PARAMETER AsArray      Emit one pretty JSON array per partition (.json) instead of NDJSON.
.PARAMETER PageSize     LDAP page size (default 1000).

.EXAMPLE
    .\Export-LdapDump.ps1
    NDJSON dump of the whole domain partition.

.EXAMPLE
    .\Export-LdapDump.ps1 -AllPartitions -Server dc01.corp.local
    Dump every partition (domain + config + schema + app partitions).

.EXAMPLE
    .\Export-LdapDump.ps1 -SearchBase "OU=Servers,DC=corp,DC=local" -AsArray

.NOTES
    Read-only. Returns every attribute your account can read. Run as a privileged
    account for the fullest snapshot. Schema/Config partitions are large -- expect
    big files when using -AllPartitions.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$SearchBase,
    [switch]$AllPartitions,
    [string]$Filter = '(objectClass=*)',
    [switch]$AsArray,
    [int]$PageSize = 1000
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

function Get-SafeFileName {
    param([string]$Name)
    if (-not $Name) { return 'partition' }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $re = '[{0}]' -f [regex]::Escape($invalid)
    return ($Name -replace $re, '_').Trim()
}

# Convert one attribute's value collection into JSON-friendly CLR values.
function ConvertTo-JsonSafeValue {
    param([string]$Name, $Values)
    $n = $Name.ToLower()
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($v in $Values) {
        if ($v -is [byte[]]) {
            try {
                switch ($n) {
                    { $_ -in 'objectsid','sidhistory' } {
                        $out.Add((New-Object System.Security.Principal.SecurityIdentifier($v, 0)).Value); break
                    }
                    'objectguid' { $out.Add(([guid][byte[]]$v).Guid); break }
                    default      { $out.Add([System.Convert]::ToBase64String($v)) }
                }
            } catch { $out.Add([System.Convert]::ToBase64String($v)) }
        }
        elseif ($v -is [datetime]) { $out.Add($v.ToString('o')) }
        else { $out.Add($v) }
    }
    if ($out.Count -eq 1) { return $out[0] }   # scalar for single-valued attrs
    return $out.ToArray()                       # array for multi-valued attrs
}

# Stream every object under $base to a JSON file. Returns the object count.
function Export-Partition {
    param([string]$Base, [string]$OutFile)

    $root = New-DirEntry -Path $Base
    $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
    $ds.Filter          = $Filter
    $ds.PageSize        = $PageSize          # page past the 1000-object server cap
    $ds.SearchScope     = 'Subtree'
    $ds.SizeLimit       = 0
    $ds.CacheResults    = $false
    $ds.ReferralChasing = 'All'

    $enc = New-Object System.Text.UTF8Encoding($false)   # UTF-8 without BOM
    $sw  = New-Object System.IO.StreamWriter($OutFile, $false, $enc)
    $count = 0
    $first = $true
    try {
        if ($AsArray) { $sw.WriteLine('[') }
        $results = $ds.FindAll()
        foreach ($r in $results) {
            $obj = [ordered]@{}
            foreach ($name in $r.Properties.PropertyNames) {
                if ($name -eq 'adspath') { continue }   # local bind path, not directory data
                $obj[$name] = ConvertTo-JsonSafeValue -Name $name -Values $r.Properties[$name]
            }
            $json = $obj | ConvertTo-Json -Compress -Depth 6
            if ($AsArray) {
                if (-not $first) { $sw.WriteLine(',') }
                $sw.Write('  '); $sw.Write($json)
                $first = $false
            } else {
                $sw.WriteLine($json)        # NDJSON: one object per line
            }
            $count++
            if ($count % 1000 -eq 0) { Write-Log "    ... $count objects" }
        }
        if ($AsArray) { $sw.WriteLine(); $sw.WriteLine(']') }
        $results.Dispose()
    } finally {
        $sw.Flush(); $sw.Close()
        try { $ds.Dispose() }   catch {}
        try { $root.Dispose() } catch {}
    }
    return $count
}

#region --- Discover domain / partitions ---

Write-Log "Binding to RootDSE ..."
$rootDse = New-DirEntry -Path 'RootDSE'
$defaultNC = $rootDse.Properties['defaultNamingContext'].Value
$namingContexts = @($rootDse.Properties['namingContexts'])
$rootDse.Dispose()
$domainFlat = ($defaultNC -replace 'DC=','' -replace ',','.')

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path (Get-Location) ("LdapDump_{0}_{1}" -f $domainFlat, $stamp)
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

# Decide which bases to dump.
$ext = if ($AsArray) { 'json' } else { 'jsonl' }
if ($SearchBase) {
    $bases = @($SearchBase)
} elseif ($AllPartitions) {
    $bases = @($namingContexts)
} else {
    $bases = @($defaultNC)
}

Write-Log "Domain   : $domainFlat"
Write-Log "Format   : $(if ($AsArray) {'JSON array'} else {'JSON Lines (NDJSON)'})"
Write-Log "Output   : $OutputPath"
Write-Log "Partitions to dump:"
$bases | ForEach-Object { Write-Log "    $_" }
Write-Host ''

#endregion

#region --- Dump ---

$manifest = @()
$grandTotal = 0
foreach ($base in $bases) {
    $label = Get-SafeFileName ($base -replace ',','_')
    $outFile = Join-Path $OutputPath ("ldapdump_{0}.{1}" -f $label, $ext)
    Write-Log "Dumping $base ..."
    try {
        $n = Export-Partition -Base $base -OutFile $outFile
        $grandTotal += $n
        $manifest += [pscustomobject]@{ Partition = $base; Objects = $n; File = (Split-Path $outFile -Leaf) }
        Write-Log ("  {0,8} objects -> {1}" -f $n, (Split-Path $outFile -Leaf)) OK
    } catch {
        Write-Log "  FAILED: $($_.Exception.Message)" ERROR
        $manifest += [pscustomobject]@{ Partition = $base; Objects = 0; File = "(failed: $($_.Exception.Message))" }
    }
}

$manifest | Export-Csv -Path (Join-Path $OutputPath '_Manifest.csv') -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Log "===== Dump complete: $grandTotal objects across $($bases.Count) partition(s) =====" OK
Write-Log "Files in: $OutputPath" OK

#endregion

#region --- Usage hints ---
Write-Host ''
Write-Log "Load the NDJSON into a database / query engine, e.g.:"
if (-not $AsArray) {
@'
  # DuckDB (SQL over the dump, no import step):
  SELECT * FROM read_json_auto('ldapdump_*.jsonl');

  # MongoDB:
  mongoimport --db ad --collection objects --file ldapdump_DC=corp_DC=local.jsonl

  # jq (e.g. all enabled-looking users):
  jq -c 'select(.objectClass | index("user"))' ldapdump_*.jsonl

  # PowerShell (read back):
  Get-Content dump.jsonl | ForEach-Object { $_ | ConvertFrom-Json }
'@ | Write-Host -ForegroundColor DarkGray
}
#endregion
