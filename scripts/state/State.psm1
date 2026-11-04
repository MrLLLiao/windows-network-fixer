#Requires -Version 7.4
Set-StrictMode -Version Latest

function Assert-NetworkSafePath {
    param([Parameter(Mandatory)][string]$Path)
    # Syntax validation must run before any filesystem probe or path canonicalization.
    Test-NetworkSafePathSyntax $Path | Out-Null
    $full=[IO.Path]::GetFullPath($Path)
    $current=$full
    while($current){
        if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse-point state paths are forbidden.'}}
        $parent=[IO.Path]::GetDirectoryName($current)
        if($parent -eq $current){break};$current=$parent
    }
    $full
}
function Write-NetworkFile {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $full=Assert-NetworkSafePath $Path
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Write-NetworkJson {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object]$Object)
    Write-NetworkFile -Path $Path -Text (ConvertTo-Json -InputObject $Object -Depth 50)
}
function New-NetworkRunDirectory {
    param([Parameter(Mandatory)][string]$StateRoot,[Parameter(Mandatory)][string]$SkillRoot)
    $state=Assert-NetworkSafePath $StateRoot
    $source=[IO.Path]::GetFullPath($SkillRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $sep=[IO.Path]::DirectorySeparatorChar
    if($state.Equals($source,[StringComparison]::OrdinalIgnoreCase) -or $state.StartsWith($source+$sep,[StringComparison]::OrdinalIgnoreCase) -or $source.StartsWith($state.TrimEnd($sep)+$sep,[StringComparison]::OrdinalIgnoreCase)){throw 'State root and skill source must be disjoint.'}
    [IO.Directory]::CreateDirectory($state)|Out-Null
    $run=Join-Path $state "run-$([guid]::NewGuid())"
    if(Test-Path -LiteralPath $run){throw 'Run already exists.'}
    [IO.Directory]::CreateDirectory($run)|Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $run 'payload'))|Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $run 'evidence'))|Out-Null
    $run
}
function Save-NetworkRun {
    param([Parameter(Mandatory)][string]$RunDirectory,[Parameter(Mandatory)][System.Collections.IDictionary]$Bundles,[Parameter(Mandatory)][object]$Baseline,[Parameter(Mandatory)][object[]]$Diagnostics,[Parameter(Mandatory)][object[]]$Validations,[Parameter(Mandatory)][object]$Proposal,[Parameter(Mandatory)][string]$SkillRoot)
    foreach($bundle in $Bundles.Values){
        $r=$bundle.record
        if($r.collectionStatus -eq 'PASS'){
            $r.payloadRef="payload/$($r.id).json"
            $path=Join-Path $RunDirectory $r.payloadRef
            Write-NetworkJson -Path $path -Object @($bundle.data)
            $r.payloadSha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        Test-NetworkContract -Type EvidenceRecord -Object $r -SkillRoot $SkillRoot
        Write-NetworkJson -Path (Join-Path $RunDirectory "evidence/$($r.id).json") -Object $r
    }
    Test-NetworkContract -Type NetworkBaseline -Object $Baseline -SkillRoot $SkillRoot
    foreach($d in $Diagnostics){Test-NetworkContract -Type DiagnosticResult -Object $d -SkillRoot $SkillRoot}
    foreach($v in $Validations){Test-NetworkContract -Type ValidationResult -Object $v -SkillRoot $SkillRoot}
    Test-NetworkContract -Type ChangeProposal -Object $Proposal -SkillRoot $SkillRoot
    Write-NetworkJson -Path (Join-Path $RunDirectory 'baseline.json') -Object $Baseline
    Write-NetworkJson -Path (Join-Path $RunDirectory 'diagnostics.json') -Object @($Diagnostics)
    Write-NetworkJson -Path (Join-Path $RunDirectory 'validation.json') -Object @($Validations)
    Write-NetworkJson -Path (Join-Path $RunDirectory 'proposal.json') -Object $Proposal
    Write-NetworkFile -Path (Join-Path $RunDirectory 'report.md') -Text (New-NetworkReport -Baseline $Baseline -Diagnostics $Diagnostics -Validations $Validations -Proposal $Proposal)
}
function New-NetworkSnapshot {
    param([Parameter(Mandatory)][string]$RunDirectory,[Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][object]$Baseline,[Parameter(Mandatory)][string]$SkillRoot)
    $run=Assert-NetworkSafePath $RunDirectory
    $manifest=New-NetworkObject -Type SnapshotManifest -Context $Context -EvidenceIds @($Baseline.evidenceIds)
    $manifest.snapshotId=$manifest.id;$manifest.baselineId=$Baseline.id;$manifest.scope=@();$manifest.hostEnvironment=@{synthetic=$Baseline.synthetic}
    $manifest.beforeStateRef='baseline.json';$manifest.diffRef=$null;$manifest.affectedComponents=@();$manifest.restorePreconditions=@()
    $manifest.payloadHashes=@(Get-ChildItem -LiteralPath $run -File -Recurse | ForEach-Object {
        $path=Assert-NetworkSafePath $_.FullName
        @{file=[IO.Path]::GetRelativePath($run,$path).Replace('\','/');sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
    } | Sort-Object {$_.file})
    $manifest.manifestHash=Get-NetworkHash (ConvertTo-Json -InputObject $manifest -Depth 50 -Compress)
    $manifest.recoverability='none';$manifest.secretRefs=@();$manifest.observationOnly=$true
    # Hash excludes itself, and includes the final recoverability fields.
    $manifest.manifestHash=''
    $manifest.manifestHash=Get-NetworkHash (ConvertTo-Json -InputObject $manifest -Depth 50 -Compress)
    Test-NetworkContract -Type SnapshotManifest -Object $manifest -SkillRoot $SkillRoot
    Write-NetworkJson -Path (Join-Path $run 'snapshot.json') -Object $manifest
    $manifest
}
function Get-NetworkRunPath {
    param([Parameter(Mandatory)][string]$StateRoot,[Parameter(Mandatory)][string]$RunId)
    if($RunId -notmatch '^run-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'){throw 'Invalid run ID.'}
    $path=Assert-NetworkSafePath (Join-Path $StateRoot $RunId)
    if(-not(Test-Path -LiteralPath $path -PathType Container)){throw 'Run not found.'};$path
}
function Test-NetworkSnapshot {
    param([Parameter(Mandatory)][string]$StateRoot,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$SkillRoot)
    $path=Get-NetworkRunPath -StateRoot $StateRoot -RunId $RunId
    $manifestPath=Assert-NetworkSafePath (Join-Path $path 'snapshot.json')
    $m=ConvertFrom-NetworkJson (Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8)
    Test-NetworkContract -Type SnapshotManifest -Object $m -SkillRoot $SkillRoot
    $expected=$m.manifestHash;$m.manifestHash=''
    if((Get-NetworkHash (ConvertTo-Json -InputObject $m -Depth 50 -Compress)) -ne $expected){throw 'Manifest integrity mismatch.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($item in $m.payloadHashes){
        $file=$item.file
        # Fixed relative grammar: no arbitrary manifest-specified path is ever opened.
        if($file -notmatch '^(baseline|diagnostics|validation|proposal)\.json$|^report\.md$|^(payload|evidence)/EvidenceRecord-[0-9a-fA-F-]{36}\.json$' -or -not $seen.Add($file)){throw 'Unsafe or duplicate snapshot entry.'}
        $full=Assert-NetworkSafePath (Join-Path $path $file)
        if((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.sha256){throw 'Payload integrity mismatch.'}
    }
    foreach($required in @('baseline.json','diagnostics.json','validation.json','proposal.json','report.md')){if(-not $seen.Contains($required)){throw 'Incomplete observation snapshot.'}}
    @{status='PASS';runId=$RunId;recoverability='none';observationOnly=$true;note='Integrity detects accidental changes, not authenticity or restore readiness.'}
}
function Get-NetworkHistory {
    param([Parameter(Mandatory)][string]$StateRoot)
    $root=Assert-NetworkSafePath $StateRoot
    if(-not(Test-Path -LiteralPath $root)){return @()}
    @(Get-ChildItem -LiteralPath $root -Directory | Where-Object {$_.Name -match '^run-[0-9a-fA-F-]{36}$' -and -not($_.Attributes -band [IO.FileAttributes]::ReparsePoint)} | ForEach-Object {
        @{runId=$_.Name;createdAt=$_.CreationTimeUtc.ToString('o');snapshotPresent=(Test-Path -LiteralPath (Join-Path $_.FullName 'snapshot.json') -PathType Leaf);integrity='NOT_RUN';recoverability='none'}
    })
}
function Compare-NetworkRuns {
    param([Parameter(Mandatory)][string]$StateRoot,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$OtherRunId,[Parameter(Mandatory)][string]$SkillRoot)
    Test-NetworkSnapshot -StateRoot $StateRoot -RunId $RunId -SkillRoot $SkillRoot | Out-Null
    Test-NetworkSnapshot -StateRoot $StateRoot -RunId $OtherRunId -SkillRoot $SkillRoot | Out-Null
    $a=Get-Content -LiteralPath (Join-Path (Get-NetworkRunPath $StateRoot $RunId) 'baseline.json') -Raw | ConvertFrom-Json -AsHashtable
    $b=Get-Content -LiteralPath (Join-Path (Get-NetworkRunPath $StateRoot $OtherRunId) 'baseline.json') -Raw | ConvertFrom-Json -AsHashtable
    if($a.hostRef -ne $b.hostRef -or $a.synthetic -ne $b.synthetic){throw 'Cross-host or synthetic/host comparisons are forbidden.'}
    foreach($key in @('environment','interfaces','addresses','routes','dns','proxies','ipInterfaces','nrpt','processes','listeners','dataDirectories','flclash')){
        $left=$a[$key];$right=$b[$key]
        $before=ConvertTo-Json -InputObject $left.value -Depth 40 -Compress
        $after=ConvertTo-Json -InputObject $right.value -Depth 40 -Compress
        @{section=$key;beforeClassification=$left.classification;afterClassification=$right.classification;changed=($before -cne $after -or $left.classification -ne $right.classification);before=$left.value;after=$right.value;note='Order-sensitive observations; no mutation or root-cause claim.'}
    }
}
Export-ModuleMember -Function *-Network*
