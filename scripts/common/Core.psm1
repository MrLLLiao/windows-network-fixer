#Requires -Version 7.4
Set-StrictMode -Version Latest

function Get-NetworkHash {
    param([Parameter(Mandatory)][string]$Text)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}
function Test-NetworkSafePathSyntax {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -ne $Path.Trim()) {
        throw 'Empty paths, surrounding whitespace and NUL characters are forbidden.'
    }
    if ($Path.IndexOf([char]0) -ge 0) {
        throw 'NUL characters are forbidden in state paths.'
    }
    # Reject namespace and device syntax before GetFullPath, Test-Path or directory creation.
    if (
        $Path -match '^[\\/]{2}' -or
        $Path -match '^[\\/]\?\?[\\/]' -or
        $Path -match '^[\\/]\?[\\/]' -or
        $Path -match '^[\\/]\.\\' -or
        $Path -match '^[\\/](?:Device|GLOBALROOT|GLOBAL\?\?)(?:[\\/]|$)' -or
        $Path -match '^[A-Za-z]:(?![\\/])' -or
        $Path -match '[\\/](?:Device|GLOBALROOT|GLOBAL\?\?)(?:[\\/]|$)'
    ) {
        throw 'UNC, extended, device-namespace and drive-relative paths are forbidden.'
    }
    if ($Path -match '(^|[\\/])(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.[^\\/]*)?([\\/]|$)') {
        throw 'DOS device names are forbidden in state paths.'
    }
    $driveMatch = [regex]::Match($Path, '^[A-Za-z]:(?<rest>.*)$')
    if ($driveMatch.Success -and $driveMatch.Groups['rest'].Value.Contains(':')) {
        throw 'Alternate data stream syntax is forbidden in state paths.'
    }
    if ($Path -match '[?*]') {
        throw 'Wildcard syntax is forbidden in state paths.'
    }
    if (@($Path -split '[\\/]+' | Where-Object { $_ -eq '..' }).Count) {
        throw 'Parent traversal is forbidden in state paths.'
    }
    $true
}

function Test-NetworkLabConfirmation {
    param(
        [bool]$GateOpen,
        [AllowEmptyString()][string]$Phrase
    )
    $GateOpen -and $Phrase -ceq 'CREATE_AND_REMOVE_ISOLATED_HYPERV_LAB_NETWORK'
}
function Test-NetworkAdministratorToken {
    if (-not $IsWindows) { return $false }
    try {
        $whoami = Join-Path $env:SystemRoot 'System32\whoami.exe'
        if (-not (Test-Path -LiteralPath $whoami -PathType Leaf)) { return $false }
        $output = @(& $whoami /groups)
        if ($LASTEXITCODE -ne 0) { return $false }
        $text = $output -join "`n"
        $text -match 'S-1-5-32-544' -and
            $text -match 'S-1-16-(?:12288|16384)'
    } catch {
        # Non-interactive or incomplete tokens remain explicitly unauthorized.
        $false
    }
}
function ConvertFrom-NetworkJson {
    param([Parameter(Mandatory)][string]$Json)
    # ConvertFrom-Json auto-converts ISO timestamps; a hash roundtrip must retain exact strings.
    function Convert-Element([System.Text.Json.JsonElement]$Element) {
        switch($Element.ValueKind.ToString()){
            'Object' {$value=[ordered]@{};foreach($property in $Element.EnumerateObject()){$value[$property.Name]=Convert-Element $property.Value};return $value}
            'Array' {$items=@(foreach($child in $Element.EnumerateArray()){,(Convert-Element $child)});return ,$items}
            'String' {return $Element.GetString()}
            'Number' {$integer=0L;if($Element.TryGetInt64([ref]$integer)){return $integer};return $Element.GetDouble()}
            'True' {return $true}
            'False' {return $false}
            'Null' {return $null}
            default {throw 'Unsupported JSON value.'}
        }
    }
    $document=[System.Text.Json.JsonDocument]::Parse($Json)
    try{Convert-Element $document.RootElement}finally{$document.Dispose()}
}
function New-NetworkContext {
    param([switch]$Synthetic)
    $identity = if ($Synthetic) { 'synthetic-user' } elseif ($IsWindows) { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } else { [Environment]::UserName }
    @{ hostRef = if($Synthetic){'synthetic-host'}else{Get-NetworkHash ([Environment]::MachineName)}; principalRef = $identity; synthetic = [bool]$Synthetic }
}
function New-NetworkObject {
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][hashtable]$Context, [string[]]$EvidenceIds = @())
    [ordered]@{ schemaVersion='1.0.0'; id="$Type-$([guid]::NewGuid())"; createdAt=[DateTimeOffset]::Now.ToString('o'); hostRef=$Context.hostRef; producer='flclash-windows-network/0.2.0'; evidenceIds=@($EvidenceIds) }
}
function New-NetworkFact {
    param([Parameter(Mandatory)][object]$Bundle)
    if ($Bundle.record.collectionStatus -eq 'PASS') {
        @{classification='OBSERVED'; value=$Bundle.data; evidenceIds=@($Bundle.record.id); unknownReason=$null}
    } else {
        @{classification='UNKNOWN'; value=$null; evidenceIds=@($Bundle.record.id); unknownReason=$Bundle.record.error.code}
    }
}
function Invoke-NetworkRead {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][scriptblock]$Read)
    $ErrorActionPreference='Stop'
    $record=New-NetworkObject -Type EvidenceRecord -Context $Context
    $record.source=@{kind='local-read';locator=$Name;collectorVersion='0.2.0'}
    $record.startedAt=[DateTimeOffset]::Now.ToString('o')
    $record.principalRef=$Context.principalRef
    $record.payloadRef=$null; $record.payloadSha256=$null
    $record.projection=@('explicit safe fields only'); $record.redactions=@('credentials, command lines, configuration bodies and error messages omitted')
    try {
        $data=@(& $Read)
        $record.collectionStatus='PASS'; $record.error=$null
    } catch {
        # Error messages can contain credentials, request headers, paths or configuration text.
        $data=$null; $record.collectionStatus='BLOCKED'
        $code=$_.Exception.GetType().Name
        if($_.Exception.Message -match '^HTTP ([1-5][0-9]{2})$'){$code="HTTP_$($Matches[1])"}
        $record.error=@{code=$code;message='Read failed; sensitive exception detail omitted. Check permissions and collector availability.'}
    }
    $record.endedAt=[DateTimeOffset]::Now.ToString('o')
    @{record=$record;data=$data}
}
function New-NetworkResource {
    param([string]$Family='NA',[string]$Kind='adapter',[string]$StableId='not-identified',[string]$Owner='unknown',[string]$Scope='current host, collector identity')
    @{kind=$Kind;stableId=$StableId;scope=$Scope;owner=$Owner;addressFamily=$Family}
}
function Test-NetworkContract {
    param([Parameter(Mandatory)][string]$Type,[Parameter(Mandatory)][object]$Object,[Parameter(Mandatory)][string]$SkillRoot)
    if($Type -notin @(
        'EvidenceRecord',
        'NetworkBaseline',
        'DiagnosticResult',
        'ChangeProposal',
        'ChangeSet',
        'SnapshotManifest',
        'ValidationResult',
        'RollbackResult',
        'TransactionJournal',
        'LabAddressSnapshot'
    )) { throw 'Unknown contract type.' }
    $schema=Join-Path $SkillRoot "schemas/$Type.schema.json"
    $json=ConvertTo-Json -InputObject $Object -Depth 50 -Compress
    if(-not (Test-Json -Json $json -SchemaFile $schema -ErrorAction SilentlyContinue)) { throw "Invalid $Type contract." }
}
Export-ModuleMember -Function *-Network*
