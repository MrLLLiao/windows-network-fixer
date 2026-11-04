#Requires -Version 7.4
[CmdletBinding()]
param([string]$OutputDirectory=(Join-Path ([IO.Path]::GetTempPath()) "flclash-network-tests-$([guid]::NewGuid())"))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
$root=Split-Path -Parent $PSScriptRoot
$entry=Join-Path $root 'scripts/entrypoints/Invoke-NetworkSkill.ps1'
$state=Join-Path $OutputDirectory 'state'
[IO.Directory]::CreateDirectory($OutputDirectory)|Out-Null
Import-Module (Join-Path $root 'scripts/common/Core.psm1') -Force -Global -DisableNameChecking
Import-Module (Join-Path $root 'scripts/discovery/Discovery.psm1') -Force -Global -DisableNameChecking
Import-Module (Join-Path $root 'scripts/state/State.psm1') -Force -Global -DisableNameChecking
Import-Module (Join-Path $root 'scripts/transactions/Transactions.psm1') -Force -Global -DisableNameChecking
Import-Module (Join-Path $root 'scripts/validation/Socket.psm1') -Force -Global -DisableNameChecking
Import-Module (Join-Path $root 'scripts/lab/Lab.Common.ps1') -Force -Global -DisableNameChecking
$script:results=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[scriptblock]$Test){
    try{& $Test | Out-Null;$script:results.Add(@{name=$Name;status='PASS';reason=$null})}
    catch{$script:results.Add(@{name=$Name;status='FAIL';reason=$_.Exception.Message})}
}
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Reject([scriptblock]$Action){$caught=$false;try{& $Action|Out-Null}catch{$caught=$true};Assert $caught 'Expected rejection.'}
function Copy-Value($Object){ConvertTo-Json -InputObject $Object -Depth 50|ConvertFrom-Json -AsHashtable}
function Rehash-Manifest([string]$Directory){
    $p=Join-Path $Directory 'snapshot.json';$m=ConvertFrom-NetworkJson (Get-Content -LiteralPath $p -Raw)
    $m.manifestHash='';$m.manifestHash=Get-NetworkHash (ConvertTo-Json -InputObject $m -Depth 50 -Compress)
    [IO.File]::WriteAllText($p,($m|ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
}
function Start-TestEchoServer([string]$Address){
    $ready=Join-Path $OutputDirectory ("echo-$($Address.Replace(':','_'))-$([guid]::NewGuid())-ready.json")
    $job=Start-Job -ArgumentList $Address,$ready -ScriptBlock {
        param($BindAddress,$ReadyPath)
        $listener=$null
        try{
            $ip=[Net.IPAddress]::Parse($BindAddress)
            $listener=[Net.Sockets.TcpListener]::new($ip,0)
            if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$listener.Server.DualMode=$false}
            $listener.Start()
            [IO.File]::WriteAllText($ReadyPath,(@{port=$listener.LocalEndpoint.Port}|ConvertTo-Json))
            $client=$listener.AcceptTcpClient()
            try{
                $stream=$client.GetStream();$buffer=[byte[]]::new(64);$read=$stream.Read($buffer,0,$buffer.Length)
                $stream.Write($buffer,0,$read)
            }finally{$client.Dispose()}
        }finally{if($listener){$listener.Stop()}}
    }
    for($i=0;$i -lt 100 -and -not(Test-Path -LiteralPath $ready);$i++){
        if($job.State -eq 'Failed'){throw 'Loopback echo server failed.'}
        Start-Sleep -Milliseconds 50
    }
    if(-not(Test-Path -LiteralPath $ready)){Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue;throw 'Loopback echo server did not become ready.'}
    @{job=$job;port=[int](Get-Content -LiteralPath $ready -Raw|ConvertFrom-Json).port}
}
function New-TestChangeSet([string]$StableId='adapter-00000000-0000-0000-0000-000000000001'){
    $context=@{hostRef='synthetic-host';principalRef='synthetic-user';synthetic=$true}
    $set=New-NetworkObject -Type ChangeSet -Context $context
    $set.proposalId="ChangeProposal-$([guid]::NewGuid())"
    $set.logicalUnit='Synthetic disposable adapter addresses'
    $set.operations=@(
        [ordered]@{
            id='addresses'
            resource=[ordered]@{
                kind='adapter'
                stableId=$StableId
                scope='disposable lab adapter only'
                owner='windows'
                addressFamily='Both'
            }
            adapter='synthetic'
            parameters=@{ipv4='192.0.2.241';ipv6='fd42:6364:786c::241'}
            preconditionIds=@('before-state')
            inverse=@{operation='restore-hash-bound-snapshot'}
            manualRecovery=@('Review exact adapter identity.')
        }
    )
    $set.expectedBeforeHash=('a'*64)
    $set.desiredAfter=@{ipv4='192.0.2.241';ipv6='fd42:6364:786c::241'}
    $set.dependencies=@()
    $set
}
function New-ApprovedTestTransaction {
    $changeSet=New-TestChangeSet
    $now=[DateTimeOffset]::Parse('2026-11-03T00:00:00Z')
    $planned=New-NetworkTransactionJournal `
        -ChangeSet $changeSet `
        -Owner windows `
        -Now $now `
        -FencingExpiresAt $now.AddMinutes(30)
    $approved=Approve-NetworkTransactionJournal `
        -Journal $planned `
        -ChangeSet $changeSet `
        -AuthorizationScope 'disposable synthetic adapter only' `
        -Principal 'synthetic-user' `
        -ExpiresAt $now.AddMinutes(10) `
        -Now $now.AddMinutes(1)
    @{
        changeSet=$changeSet
        approved=$approved
        now=$now
    }
}
Check 'all PowerShell files parse and carry UTF-8 BOM' {
    foreach($file in (Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {$_.Extension -in @('.ps1','.psm1')})){
        $bytes=[IO.File]::ReadAllBytes($file.FullName)
        Assert ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) "Missing BOM: $($file.Name)"
        $tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)|Out-Null
        Assert ($errors.Count -eq 0) "Parse errors: $($file.Name)"
    }
}
$script:first=& $entry -Fixture -StateRoot $state
$script:second=& $entry -Fixture -StateRoot $state -Intent baseline
$context=New-NetworkContext -Synthetic
$baseline=Get-Content -LiteralPath (Join-Path $first.runDirectory 'baseline.json') -Raw|ConvertFrom-Json -AsHashtable
$diagnostics=@(Get-Content -LiteralPath (Join-Path $first.runDirectory 'diagnostics.json') -Raw|ConvertFrom-Json -AsHashtable)
$validation=@(Get-Content -LiteralPath (Join-Path $first.runDirectory 'validation.json') -Raw|ConvertFrom-Json -AsHashtable)
$proposal=Get-Content -LiteralPath (Join-Path $first.runDirectory 'proposal.json') -Raw|ConvertFrom-Json -AsHashtable
Check 'offline fixture generates complete schema-validated run' {Assert ($first.status -eq 'PASS' -and $first.synthetic -and $first.collectionBlocked -eq 0) 'Fixture failed.'}
Check 'fixture provenance is explicit in baseline and report' {
    Assert ($baseline.synthetic -and $baseline.hostRef -eq 'synthetic-host') 'Lost fixture provenance.'
    Assert ((Get-Content -LiteralPath $first.report -Raw) -match 'SYNTHETIC FIXTURE') 'Report lacks provenance.'
}
Check 'independent family diagnostics and no invented root cause' {
    Assert ($diagnostics.Count -eq 2) 'Expected two independent results.'
    Assert ($diagnostics[0].family -eq 'IPv4' -and $diagnostics[1].family -eq 'IPv6') 'Families merged.'
    Assert ($null -eq $diagnostics[0].rootCause -and $null -eq $diagnostics[1].rootCause) 'Invented root cause.'
}
Check 'TUN hypothesis does not become native success' {
    Assert ($diagnostics[1].hypothesis -match 'intercept') 'TUN route not surfaced.'
    Assert ($validation[1].status -eq 'NOT_RUN') 'Native success fabricated.'
}
Check 'snapshot integrity verifies actual bytes' {Assert ((& $entry -Intent integrity -StateRoot $state -RunId $first.runId).status -eq 'PASS') 'Integrity failed.'}
Check 'identical fixture sections compare unchanged' {
    $diff=@(& $entry -Intent diff -StateRoot $state -RunId $first.runId -OtherRunId $second.runId)
    Assert ($diff.Count -eq 12 -and @($diff|Where-Object changed).Count -eq 0) 'False fixture difference.'
}
Check 'history records observations without restore claim' {
    $history=@(& $entry -Intent history -StateRoot $state)
    Assert ($history.Count -eq 2 -and $history[0].recoverability -eq 'none') 'History invalid.'
}
Check 'apply and rollback explicitly BLOCKED without writes' {
    foreach($intent in @('apply','rollback')){$r=& $entry -Intent $intent -StateRoot (Join-Path $OutputDirectory 'must-not-exist');Assert ($r.status -eq 'BLOCKED') 'Mutation was not blocked.'}
    Assert (-not(Test-Path -LiteralPath (Join-Path $OutputDirectory 'must-not-exist'))) 'Blocked intent wrote state.'
}
Check 'fixture forbids DNS or controller network probes' {
    Reject {& $entry -Fixture -ProbeDns -StateRoot $state}
    Reject {& $entry -Fixture -ControllerUri 'http://127.0.0.1:19090/' -StateRoot $state}
}
Check 'read failure preserves BLOCKED null and suppresses secrets' {
    $r=Invoke-NetworkRead -Name 'denied' -Context $context -Read {throw 'sentinel-private-password'}
    Assert ($r.record.collectionStatus -eq 'BLOCKED' -and $null -eq $r.data) 'Failure became empty success.'
    Assert (($r|ConvertTo-Json -Depth 15) -notmatch 'sentinel-private-password') 'Error leaked secret.'
    $fact=New-NetworkFact $r;Assert ($fact.classification -eq 'UNKNOWN' -and $null -eq $fact.value) 'Lost UNKNOWN.'
}
Check 'successful empty collection stays distinguishable' {
    $r=Invoke-NetworkRead -Name 'empty' -Context $context -Read {@()}
    Assert ($r.record.collectionStatus -eq 'PASS' -and $null -ne $r.data -and $r.data.Count -eq 0) 'Empty success lost.'
}
Check 'nonterminating read errors cannot become empty PASS' {
    $r=Invoke-NetworkRead -Name 'nonterminating' -Context $context -Read {Write-Error 'sentinel-private-error'}
    Assert ($r.record.collectionStatus -eq 'BLOCKED' -and $null -eq $r.data) 'Nonterminating failure became PASS.'
    Assert (($r|ConvertTo-Json -Depth 15) -notmatch 'sentinel-private-error') 'Error stream leaked secret.'
}
Check 'authentication status code retained safely' {
    $r=Invoke-NetworkRead -Name 'controller' -Context $context -Read {throw 'HTTP 401'}
    Assert ($r.record.error.code -eq 'HTTP_401' -and $r.record.collectionStatus -eq 'BLOCKED') '401 misclassified.'
}
Check 'collector failure cannot imply absent network configuration' {
    $b=Copy-Value $baseline;$b.addresses.classification='UNKNOWN';$b.addresses.value=$null;$b.addresses.unknownReason='AccessDenied'
    $d=Get-NetworkFamilyDiagnostics -Baseline $b -Context $context -Family IPv6
    Assert ($d.observation -match '^UNKNOWN' -and $null -eq $d.rootCause) 'Failed read inferred no network.'
}
Check 'no tunnel interfaces is valid data not a strict-mode crash' {
    $b=Copy-Value $baseline;$b.interfaces.value=@($b.interfaces.value|Where-Object {$_.InterfaceDescription -ne 'Meta Tunnel'})
    $d=Get-NetworkFamilyDiagnostics -Baseline $b -Context $context -Family IPv6
    Assert ($null -eq $d.hypothesis) 'Invented tunnel hypothesis.'
}
Check 'IPv6 address absence never proves upstream capability' {
    $b=Copy-Value $baseline;$b.addresses.value=@($b.addresses.value|Where-Object AddressFamily -eq IPv4)
    $d=Get-NetworkFamilyDiagnostics -Baseline $b -Context $context -Family IPv6
    Assert (($d.openQuestions -join ' ') -match 'upstream support is not determined') 'Unsupported upstream claim.'
}
Check 'unsafe controller URI rejected before connecting' {
    foreach($uri in @('http://example.com/','http://localhost/','https://127.0.0.1/','http://127.0.0.1/configs','http://user:password@127.0.0.1/','http://127.0.0.1/?secret=x')){Reject {Get-NetworkController -ControllerUri $uri -Context $context}}
}
Check 'unowned loopback does not get probed' {
    $r=Get-NetworkController -ControllerUri 'http://127.0.0.1:1/' -Context $context
    Assert ($r.version.record.collectionStatus -eq 'BLOCKED' -and $r.configs.record.collectionStatus -eq 'BLOCKED') 'Unowned listener accepted.'
}
Check 'state cannot live inside skill source' {Reject {New-NetworkRunDirectory -StateRoot (Join-Path $root 'state') -SkillRoot $root}}
Check 'state cannot be an ancestor of skill source' {Reject {New-NetworkRunDirectory -StateRoot (Split-Path -Parent $root) -SkillRoot $root}}
Check 'existing files cannot be overwritten' {
    $p=Join-Path $OutputDirectory 'keep.txt';Write-NetworkFile -Path $p -Text 'original'
    Reject {Write-NetworkFile -Path $p -Text 'replacement'}
    Assert ((Get-Content -LiteralPath $p -Raw) -eq 'original') 'File overwritten.'
}
Check 'invalid run identifiers rejected' {foreach($id in @('../other','C:\other','run-../other','run-xyz')){Reject {Get-NetworkRunPath -StateRoot $state -RunId $id}}}
Check 'reparse state roots rejected' {
    $target=Join-Path $OutputDirectory 'target';[IO.Directory]::CreateDirectory($target)|Out-Null
    $link=Join-Path $OutputDirectory 'junction'
    if($IsWindows){New-Item -ItemType Junction -Path $link -Target $target|Out-Null}else{New-Item -ItemType SymbolicLink -Path $link -Target $target|Out-Null}
    Reject {Assert-NetworkSafePath (Join-Path $link 'child')}
}
Check 'payload modification detected' {
    $p=Join-Path $second.runDirectory 'report.md';[IO.File]::AppendAllText($p,'tampered')
    Reject {Test-NetworkSnapshot -StateRoot $state -RunId $second.runId -SkillRoot $root}
}
Check 'untrusted manifest cannot read traversal even with matching manifest hash' {
    $new=& $entry -Fixture -StateRoot $state
    $p=Join-Path $new.runDirectory 'snapshot.json';$m=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json -AsHashtable
    $m.payloadHashes[0].file='../outside.json';[IO.File]::WriteAllText($p,($m|ConvertTo-Json -Depth 50));Rehash-Manifest $new.runDirectory
    Reject {Test-NetworkSnapshot -StateRoot $state -RunId $new.runId -SkillRoot $root}
}
Check 'manifest missing required observation entries rejected' {
    $new=& $entry -Fixture -StateRoot $state
    $p=Join-Path $new.runDirectory 'snapshot.json';$m=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json -AsHashtable
    $m.payloadHashes=@($m.payloadHashes|Where-Object file -ne 'baseline.json');[IO.File]::WriteAllText($p,($m|ConvertTo-Json -Depth 50));Rehash-Manifest $new.runDirectory
    Reject {Test-NetworkSnapshot -StateRoot $state -RunId $new.runId -SkillRoot $root}
}
Check 'partial runs appear in history without being complete' {
    $partial=New-NetworkRunDirectory -StateRoot $state -SkillRoot $root
    $row=@(Get-NetworkHistory $state|Where-Object {$_.runId -eq (Split-Path $partial -Leaf)})[0]
    Assert (-not $row.snapshotPresent -and $row.integrity -eq 'NOT_RUN') 'Partial observation accepted.'
}
Check 'schemas reject undeclared properties' {$bad=Copy-Value $baseline;$bad.unexpected='not allowed';Reject {Test-NetworkContract -Type NetworkBaseline -Object $bad -SkillRoot $root}}
Check 'schema enforces UNKNOWN null value' {$bad=Copy-Value $baseline;$bad.flclash.value=@{};Reject {Test-NetworkContract -Type NetworkBaseline -Object $bad -SkillRoot $root}}
Check 'schema enforces observed evidence references' {$bad=Copy-Value $baseline;$bad.addresses.evidenceIds=@();Reject {Test-NetworkContract -Type NetworkBaseline -Object $bad -SkillRoot $root}}
Check 'schema rejects fabricated validation PASS' {$bad=Copy-Value $validation[0];$bad.status='PASS';Reject {Test-NetworkContract -Type ValidationResult -Object $bad -SkillRoot $root}}
Check 'schema rejects failed test without reason' {$bad=Copy-Value $validation[0];$bad.status='FAIL';$bad.failureReason=$null;Reject {Test-NetworkContract -Type ValidationResult -Object $bad -SkillRoot $root}}
Check 'schema blocks executable proposal' {$bad=Copy-Value $proposal;$bad.executable=$true;Reject {Test-NetworkContract -Type ChangeProposal -Object $bad -SkillRoot $root}}
Check 'evidence plans map diagnostics and family-specific source evidence' {
    foreach($d in $diagnostics){
        $steps=@($proposal.evidenceSteps|Where-Object {$_.diagnosticId -eq $d.id})
        Assert ($steps.Count -ge 2) 'Diagnostic has no targeted follow-up steps.'
        foreach($step in $steps){
            Assert ($step.family -eq $d.family -and $step.evidenceIds.Count -gt 0) 'Evidence step lost family or evidence references.'
            Assert ($step.status -eq 'NOT_RUN' -and -not $step.networkChange) 'Evidence plan claims execution or mutation.'
            Assert (@($proposal.validationPlan|Where-Object testId -eq $step.id).Count -eq 1) 'Evidence step lacks acceptance contract.'
        }
    }
    Assert ($proposal.resource.owner -eq 'unknown' -and -not $proposal.executable -and $null -eq $proposal.authorization) 'Evidence plan invented ownership or authorization.'
}
Check 'report exposes each proposal step with supporting evidence' {
    $report=Get-Content -LiteralPath $first.report -Raw -Encoding UTF8
    foreach($step in $proposal.evidenceSteps){
        Assert ($report.Contains($step.id) -and $report.Contains($step.action) -and $report.Contains($step.expectedObservation)) 'Report omitted actionable proposal.'
        foreach($evidenceId in $step.evidenceIds){Assert ($report.Contains($evidenceId)) 'Report omitted proposal evidence.'}
    }
}
Check 'blocked collector plans request missing facts without inventing network failure' {
    $b=Copy-Value $baseline;$b.addresses.classification='UNKNOWN';$b.addresses.value=$null;$b.addresses.unknownReason='AccessDenied'
    $d=@(Get-NetworkDiagnostics -Baseline $b -Context $context)
    $p=New-NetworkProposal -Baseline $b -Diagnostics $d -Context $context
    Test-NetworkContract -Type ChangeProposal -Object $p -SkillRoot $root
    $contexts=@($p.evidenceSteps|Where-Object {$_.id -like 'context-*'})
    Assert ($contexts.Count -eq 2 -and @($contexts|Where-Object {$_.action.Contains('addresses')}).Count -eq 2) 'Blocked source not surfaced in family plans.'
    Assert (@($p.evidenceSteps|Where-Object {$_.status -ne 'NOT_RUN' -or $_.networkChange}).Count -eq 0) 'Planned collection masquerades as executed.'
}
Check 'schema rejects absent steps and fabricated executed evidence plan' {
    $bad=Copy-Value $proposal;$bad.Remove('evidenceSteps');Reject {Test-NetworkContract -Type ChangeProposal -Object $bad -SkillRoot $root}
    $bad=Copy-Value $proposal;$bad.evidenceSteps[0].status='PASS';Reject {Test-NetworkContract -Type ChangeProposal -Object $bad -SkillRoot $root}
}
Check 'schema requires evidence for confirmed diagnostic' {$bad=Copy-Value $diagnostics[0];$bad.confidence='confirmed';Reject {Test-NetworkContract -Type DiagnosticResult -Object $bad -SkillRoot $root}}
Check 'snapshot schema disallows restore capability' {$p=Join-Path $first.runDirectory 'snapshot.json';$bad=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json -AsHashtable;$bad.recoverability='fullConditional';Reject {Test-NetworkContract -Type SnapshotManifest -Object $bad -SkillRoot $root}}
Check 'future ChangeSet contract validates structure only' {
    $set=New-NetworkObject -Type ChangeSet -Context $context
    $set.proposalId=$proposal.id;$set.logicalUnit='synthetic single resource';$set.operations=@();$set.expectedBeforeHash=('0'*64);$set.desiredAfter=@{};$set.dependencies=@()
    Test-NetworkContract -Type ChangeSet -Object $set -SkillRoot $root
    $set.Remove('expectedBeforeHash');Reject {Test-NetworkContract -Type ChangeSet -Object $set -SkillRoot $root}
}
Check 'future RollbackResult cannot claim restore without validation' {
    $r=New-NetworkObject -Type RollbackResult -Context $context
    $r.changeId="ChangeSet-$([guid]::NewGuid())";$r.snapshotId="SnapshotManifest-$([guid]::NewGuid())";$r.feasibility=@{};$r.attemptedOperations=@();$r.restoredResources=@();$r.unrestoredResources=@();$r.validationIds=@();$r.finalState='MANUAL_RECOVERY_REQUIRED';$r.manualSteps=@('Synthetic only; no restore attempted.')
    Test-NetworkContract -Type RollbackResult -Object $r -SkillRoot $root
    $r.finalState='ROLLED_BACK';Reject {Test-NetworkContract -Type RollbackResult -Object $r -SkillRoot $root}
}
Check 'evidence schema rejects failed read with payload' {
    $r=Invoke-NetworkRead -Name 'denied' -Context $context -Read {throw 'denied'}
    Test-NetworkContract -Type EvidenceRecord -Object $r.record -SkillRoot $root
    $r.record.payloadRef='payload/forbidden.json';Reject {Test-NetworkContract -Type EvidenceRecord -Object $r.record -SkillRoot $root}
}
Check 'release version and producer compatibility policy are coherent' {
    $manifest=Get-Content -LiteralPath (Join-Path $root 'manifests/compatibility.json') -Raw|ConvertFrom-Json
    $skill=Get-Content -LiteralPath (Join-Path $root 'SKILL.md') -Raw
    Assert ($manifest.version -eq '1.1.0') 'Compatibility manifest version is not 1.1.0.'
    Assert ($skill -match '(?m)^\s*name:\s*windows-network-fixer\s*$') 'SKILL name is not windows-network-fixer.'
    Assert ($skill -match '(?m)^\s+version:\s*"1\.1\.0"\s*$') 'SKILL metadata version is not 1.1.0.'
    $newObject=New-NetworkObject -Type EvidenceRecord -Context $context
    Assert ($newObject.producer -eq 'flclash-windows-network/0.2.0') 'New objects do not use producer 0.2.0.'
    foreach($name in @('EvidenceRecord','NetworkBaseline','DiagnosticResult','ChangeProposal','SnapshotManifest','ValidationResult')){
        $schema=Get-Content -LiteralPath (Join-Path $root "schemas/$name.schema.json") -Raw|ConvertFrom-Json -AsHashtable
        Assert ($schema.properties.producer.enum -contains 'flclash-windows-network/0.1.0' -and $schema.properties.producer.enum -contains 'flclash-windows-network/0.2.0') "$name producer compatibility missing."
    }
    foreach($name in @('ChangeSet','RollbackResult','TransactionJournal')){
        $schema=Get-Content -LiteralPath (Join-Path $root "schemas/$name.schema.json") -Raw|ConvertFrom-Json -AsHashtable
        Assert ($schema.properties.producer.const -eq 'flclash-windows-network/0.2.0') "$name incorrectly accepts legacy mutation producer."
    }
}
Check 'state module is tracked and cannot be swallowed by ignore rules' {
    if(Test-Path -LiteralPath (Join-Path $root '.git')){
        $inside=& git -C $root rev-parse --is-inside-work-tree 2>$null
        if($inside -eq 'true'){
            & git -C $root ls-files --error-unmatch 'scripts/state/State.psm1' 2>$null | Out-Null
            Assert ($LASTEXITCODE -eq 0) 'scripts/state/State.psm1 is not tracked by Git.'
            $ignored=& git -C $root check-ignore -- 'scripts/state/State.psm1' 2>$null
            Assert ($LASTEXITCODE -ne 0 -and [string]::IsNullOrWhiteSpace(($ignored -join ''))) 'scripts/state/State.psm1 is still excluded by .gitignore.'
        }
    }
}
Check 'transaction module export set contains no network write cmdlets' {
    $expected=@(
        'Approve-NetworkTransactionJournal',
        'Assert-NetworkTransactionApproval',
        'Assert-NetworkTransactionJournalIntegrity',
        'ConvertTo-NetworkCanonicalJson',
        'Get-NetworkRecoveryDecision',
        'Move-NetworkTransactionJournal',
        'New-NetworkRollbackResult',
        'New-NetworkTransactionJournal'
    ) | Sort-Object
    $actual=@(Get-Command -Module Transactions -CommandType Function).Name|Sort-Object
    Assert ((($actual|ConvertTo-Json -Compress) -ceq ($expected|ConvertTo-Json -Compress))) 'Transaction exports changed unexpectedly.'
    $forbidden=@('New-NetIPAddress','Remove-NetIPAddress','New-NetRoute','Remove-NetRoute','Set-DnsClientServerAddress','Set-NetIPInterface')
    Assert (-not @($actual|Where-Object {$_ -in $forbidden})) 'Transaction module exported a network write command.'
}
Check '0.1.0 observation snapshots remain readable for integrity and diff' {
    $legacy=& $entry -Fixture -StateRoot $state
    $manifestPath=Join-Path $legacy.runDirectory 'snapshot.json'
    $manifest=ConvertFrom-NetworkJson (Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8)
    $manifest.producer='flclash-windows-network/0.1.0'
    [IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
    Rehash-Manifest $legacy.runDirectory
    $legacyReloaded=ConvertFrom-NetworkJson (Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8)
    Test-NetworkContract -Type SnapshotManifest -Object $legacyReloaded -SkillRoot $root
    Assert ((& $entry -Intent integrity -StateRoot $state -RunId $legacy.runId).status -eq 'PASS') 'Legacy integrity failed.'
    $diff=@(& $entry -Intent diff -StateRoot $state -RunId $first.runId -OtherRunId $legacy.runId)
    Assert ($diff.Count -eq 12 -and @($diff|Where-Object changed).Count -eq 0) 'Legacy diff failed.'
}
Check 'unsafe Windows path namespaces reject before state directory creation' {
    $probeRoot=Join-Path $OutputDirectory 'path-gate-must-not-exist'
    foreach($unsafe in @(
        "\\?\$probeRoot\child",
        "\\?\UNC\server\share\child",
        "\\.\pipe\flclash-test",
        "\\server\share\child"
    )){
        Reject {New-NetworkRunDirectory -StateRoot $unsafe -SkillRoot $root}
    }
    Assert (-not(Test-Path -LiteralPath $probeRoot)) 'Unsafe path gate created a destination.'
}
Check 'controller executable ownership requires trusted root or exact verified path' {
    $programFiles=[Environment]::GetFolderPath('ProgramFiles')
    $trusted=Join-Path $programFiles 'FlClash/FlClashCore.exe'
    $sibling=Join-Path $programFiles 'FlClashEvil/FlClashCore.exe'
    $verified='D:\Verified\FlClash\FlClashCore.exe'
    Assert (Test-NetworkCoreExecutablePath -ProcessPath $trusted) 'Trusted install root rejected.'
    Reject {Test-NetworkCoreExecutablePath -ProcessPath $sibling}
    Assert (Test-NetworkCoreExecutablePath -ProcessPath $verified -VerifiedExecutablePath $verified) 'Exact verified path rejected.'
    Reject {Test-NetworkCoreExecutablePath -ProcessPath $sibling -VerifiedExecutablePath $verified}
}
Check 'transaction journal happy path commits only with validation evidence' {
    $fixture=New-ApprovedTestTransaction
    $planned=New-NetworkTransactionJournal `
        -ChangeSet $fixture.changeSet `
        -Owner windows `
        -Now $fixture.now `
        -FencingExpiresAt $fixture.now.AddMinutes(30)
    Test-NetworkContract -Type TransactionJournal -Object $planned -SkillRoot $root
    $approved=$fixture.approved
    Test-NetworkContract -Type TransactionJournal -Object $approved -SkillRoot $root
    $applying=Move-NetworkTransactionJournal -Journal $approved -NextState APPLYING -Now $fixture.now.AddMinutes(2)
    $validating=Move-NetworkTransactionJournal -Journal $applying -NextState VALIDATING -Now $fixture.now.AddMinutes(3)
    Reject {Move-NetworkTransactionJournal -Journal $validating -NextState COMMITTED -Now $fixture.now.AddMinutes(4)}
    $validationId="ValidationResult-$([guid]::NewGuid())"
    $committed=Move-NetworkTransactionJournal -Journal $validating -NextState COMMITTED -Now $fixture.now.AddMinutes(4) -ValidationIds @($validationId)
    Assert ($committed.state -eq 'COMMITTED' -and $committed.validationIds -contains $validationId) 'Commit semantics failed.'
    Test-NetworkContract -Type TransactionJournal -Object $committed -SkillRoot $root
    Reject {Move-NetworkTransactionJournal -Journal $committed -NextState VALIDATING -Now $fixture.now.AddMinutes(5)}
}
Check 'expired approval and fencing reject APPLYING start' {
    $fixture=New-ApprovedTestTransaction
    Reject {Move-NetworkTransactionJournal -Journal $fixture.approved -NextState APPLYING -Now $fixture.now.AddMinutes(11)}
    $late=New-NetworkTransactionJournal `
        -ChangeSet $fixture.changeSet `
        -Owner windows `
        -Now $fixture.now `
        -FencingExpiresAt $fixture.now.AddMinutes(5)
    Reject {
        Approve-NetworkTransactionJournal `
            -Journal $late `
            -ChangeSet $fixture.changeSet `
            -AuthorizationScope 'too long' `
            -Principal 'synthetic-user' `
            -ExpiresAt $fixture.now.AddMinutes(6) `
            -Now $fixture.now.AddMinutes(1)
    }
}
Check 'approval rejects target, before-state and owner drift' {
    $fixture=New-ApprovedTestTransaction
    $targetDrift=New-TestChangeSet 'adapter-different'
    Reject {Assert-NetworkTransactionApproval -Journal $fixture.approved -ChangeSet $targetDrift}
    $hashDrift=Copy-Value $fixture.changeSet
    $hashDrift.expectedBeforeHash=('b'*64)
    Reject {Assert-NetworkTransactionApproval -Journal $fixture.approved -ChangeSet $hashDrift}
    $ownerDrift=Copy-Value $fixture.changeSet
    $ownerDrift.operations[0].resource.owner='unknown'
    Reject {New-NetworkTransactionJournal -ChangeSet $ownerDrift -Owner windows -Now $fixture.now}
    $principalDrift=Copy-Value $fixture.approved
    $principalDrift.approval.principal='different-principal'
    Reject {Assert-NetworkTransactionApproval -Journal $principalDrift}
    $approvalTimeDrift=Copy-Value $fixture.approved
    $approvalTimeDrift.approval.approvedAt=$fixture.now.AddMinutes(3).ToString('o')
    Reject {Assert-NetworkTransactionApproval -Journal $approvalTimeDrift}
}
Check 'approval binds the full ChangeSet and journal Schema requires its hash' {
    $fixture=New-ApprovedTestTransaction
    $originalHash=Get-NetworkHash (ConvertTo-NetworkCanonicalJson $fixture.changeSet)
    $parameterDrift=Copy-Value $fixture.changeSet
    $parameterDrift.operations[0].parameters.ipv4='192.0.2.242'
    $driftHash=Get-NetworkHash (ConvertTo-NetworkCanonicalJson $parameterDrift)
    Assert ($originalHash -ne $driftHash) 'Operation parameter drift did not change the canonical ChangeSet hash.'
    Reject {Assert-NetworkTransactionApproval -Journal $fixture.approved -ChangeSet $parameterDrift}
    $missingHash=Copy-Value $fixture.approved
    $missingHash.Remove('changeSetHash')
    Reject {Test-NetworkContract -Type TransactionJournal -Object $missingHash -SkillRoot $root}
}
Check 'illegal state transitions are rejected without mutating the source journal' {
    $fixture=New-ApprovedTestTransaction
    $before=$fixture.approved|ConvertTo-Json -Depth 50 -Compress
    Reject {Move-NetworkTransactionJournal -Journal $fixture.approved -NextState VALIDATING -Now $fixture.now.AddMinutes(2)}
    Assert (($fixture.approved|ConvertTo-Json -Depth 50 -Compress) -ceq $before) 'Rejected transition mutated the source journal.'
}
Check 'journal rejects tampered transition chains, sequence rollback and final-state mismatch' {
    $fixture=New-ApprovedTestTransaction
    $reasonDrift=Copy-Value $fixture.approved
    $reasonDrift.transitions[1].reason='Tampered after approval.'
    Reject {Assert-NetworkTransactionJournalIntegrity -Journal $reasonDrift}
    $chainDrift=Copy-Value $fixture.approved
    $chainDrift.transitions[1].previousEventHash=('f'*64)
    Reject {Assert-NetworkTransactionJournalIntegrity -Journal $chainDrift}
    $sequenceDrift=Copy-Value $fixture.approved
    $sequenceDrift.transitions[1].sequence=1
    Reject {Assert-NetworkTransactionJournalIntegrity -Journal $sequenceDrift}
    $stateDrift=Copy-Value $fixture.approved
    $stateDrift.state='APPLYING'
    Reject {Assert-NetworkTransactionJournalIntegrity -Journal $stateDrift}
    $missingEventHash=Copy-Value $fixture.approved
    $missingEventHash.transitions[0].Remove('eventHash')
    Reject {Test-NetworkContract -Type TransactionJournal -Object $missingEventHash -SkillRoot $root}
}
Check 'interrupted transaction decisions never authorize blind replay' {
    $fixture=New-ApprovedTestTransaction
    $applying=Move-NetworkTransactionJournal -Journal $fixture.approved -NextState APPLYING -Now $fixture.now.AddMinutes(2)
    $atBefore=Get-NetworkRecoveryDecision -Journal $applying -CurrentStateHash $applying.beforeStateHash
    $atDesired=Get-NetworkRecoveryDecision -Journal $applying -CurrentStateHash $applying.desiredAfterHash
    $partial=Get-NetworkRecoveryDecision -Journal $applying -CurrentStateHash ('c'*64)
    Assert ($atBefore.decision -eq 'APPLY_NOT_OBSERVED_REOBSERVE') 'Before-state decision changed.'
    Assert ($atDesired.decision -eq 'APPLIED_AWAITING_INDEPENDENT_VALIDATION') 'Desired-state decision changed.'
    Assert ($partial.decision -eq 'PARTIAL_OR_DRIFT_MANUAL_REVIEW') 'Partial decision changed.'
    foreach($decision in @($atBefore,$atDesired,$partial)){Assert (-not $decision.safeToReplay -and -not $decision.automaticWriteAllowed) 'Recovery decision allowed replay.'}
}
Check 'recovery-check entrypoint validates journal and approval binding without mutation' {
    $fixture=New-ApprovedTestTransaction
    $applying=Move-NetworkTransactionJournal -Journal $fixture.approved -NextState APPLYING -Now $fixture.now.AddMinutes(2)
    $journalPath=Join-Path $OutputDirectory 'recovery-journal.json'
    $changeSetPath=Join-Path $OutputDirectory 'recovery-changeset.json'
    [IO.File]::WriteAllText($journalPath,($applying|ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($changeSetPath,($fixture.changeSet|ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
    $decision=& $entry `
        -Intent recovery-check `
        -JournalPath $journalPath `
        -CurrentStateHash $applying.beforeStateHash `
        -ChangeSetPath $changeSetPath
    Assert ($decision.decision -eq 'APPLY_NOT_OBSERVED_REOBSERVE') 'Recovery entrypoint decision changed.'
    Assert (-not $decision.safeToReplay -and -not $decision.automaticWriteAllowed) 'Recovery entrypoint allowed write.'
}
Check 'ROLLED_BACK requires validation and zero unrestored resources' {
    $fixture=New-ApprovedTestTransaction
    $applying=Move-NetworkTransactionJournal -Journal $fixture.approved -NextState APPLYING -Now $fixture.now.AddMinutes(2)
    $rolling=Move-NetworkTransactionJournal -Journal $applying -NextState ROLLING_BACK -Now $fixture.now.AddMinutes(3)
    Reject {Move-NetworkTransactionJournal -Journal $rolling -NextState ROLLED_BACK -Now $fixture.now.AddMinutes(4)}
    $validationId="ValidationResult-$([guid]::NewGuid())"
    Reject {Move-NetworkTransactionJournal -Journal $rolling -NextState ROLLED_BACK -Now $fixture.now.AddMinutes(4) -ValidationIds @($validationId) -UnrestoredResourceIds @('adapter-1')}
    $rolled=Move-NetworkTransactionJournal -Journal $rolling -NextState ROLLED_BACK -Now $fixture.now.AddMinutes(4) -ValidationIds @($validationId)
    Assert ($rolled.state -eq 'ROLLED_BACK' -and $rolled.unrestoredResourceIds.Count -eq 0) 'Valid rollback terminal state failed.'
    Test-NetworkContract -Type TransactionJournal -Object $rolled -SkillRoot $root
}
Check 'same-host IPv4 and IPv6 nonce echo passes with bind before connect' {
    foreach($address in @('127.0.0.1','::1')){
        $server=Start-TestEchoServer $address
        try{
            $result=Invoke-NetworkSocketProbe `
                -Address $address `
                -Port $server.port `
                -Nonce 'socket-probe-nonce-0123456789abcdef' `
                -TimeoutMilliseconds 3000
        }finally{
            Stop-Job -Job $server.job -ErrorAction SilentlyContinue
            Remove-Job -Job $server.job -Force -ErrorAction SilentlyContinue
        }
        Assert ($result.status -eq 'PASS' -and $result.nonceMatched -and $result.bindSucceeded -and $result.connectAttempted) "Loopback probe failed for $address."
        Assert ($result.nonceSha256 -match '^[0-9a-f]{64}$' -and $result.clientClosed -and $null -eq $result.listenerClosed) "Loopback probe cleanup or nonce digest failed for $address."
    }
}
Check 'unassigned IPv4 and IPv6 bind failures preserve 10049 and no connect' {
    foreach($address in @('192.0.2.254','fd42:6364:786c::254')){
        $result=Invoke-NetworkSocketProbe -Address $address -Port 1 -Nonce 'negative-bind-nonce' -TimeoutMilliseconds 1000
        Assert ($result.status -eq 'FAIL') "Unexpected success for unassigned $address."
        Assert ($result.failedStage -eq 'bind' -and $result.nativeError -eq 10049) "Wrong bind failure for $address."
        Assert (-not $result.connectAttempted -and -not $result.nonceMatched -and -not $result.bindSucceeded) "Connect/nonce attempted after bind failure for $address."
    }
}
Check 'lab intent without confirmation performs zero state and network writes' {
    $blockedState=Join-Path $OutputDirectory 'lab-gate-must-not-exist'
    $blocked=& $entry -Intent lab -StateRoot $blockedState
    Assert ($blocked.status -eq 'BLOCKED' -and -not $blocked.networkChanges) 'Unconfirmed lab did not block.'
    Assert (-not(Test-Path -LiteralPath $blockedState)) 'Unconfirmed lab created state.'
    $engineState=Join-Path $OutputDirectory 'lab-engine-gate-must-not-exist'
    $engineResult=& (Join-Path $root 'scripts/lab/Invoke-Lab.ps1') -RunDirectory $engineState -ConfirmLabMutation
    Assert ($engineResult.status -eq 'BLOCKED') 'Direct engine accepted one-gate confirmation.'
    Assert (-not(Test-Path -LiteralPath $engineState)) 'Direct engine gate created state.'
}
Check 'lab confirmation requires both switch and exact phrase' {
    $phrase='CREATE_AND_REMOVE_ISOLATED_HYPERV_LAB_NETWORK'
    $command=Get-Command $entry
    Assert ($command.Parameters.ContainsKey('WhatIf') -and $command.Parameters.ContainsKey('LabConfirmation')) 'Public lab entry lacks WhatIf or exact confirmation phrase.'
    Assert (-not(Test-NetworkLabConfirmation -GateOpen $false -Phrase $phrase)) 'Phrase bypassed the confirmation switch.'
    Assert (-not(Test-NetworkLabConfirmation -GateOpen $true -Phrase 'create_and_remove_isolated_hyperv_lab_network')) 'Wrong-case phrase passed.'
    Assert (-not(Test-NetworkLabConfirmation -GateOpen $true -Phrase '$phrase')) 'Literal placeholder passed.'
    Assert (Test-NetworkLabConfirmation -GateOpen $true -Phrase $phrase) 'Exact confirmation tuple rejected.'
}
Check 'lab cleanup failure status becomes manual recovery required' {
    Assert ((Get-LabTerminalStatus -Failure $null -Preview $false) -eq 'PASS') 'Clean lab did not map to PASS.'
    Assert ((Get-LabTerminalStatus -Failure $null -Preview $true) -eq 'NOT_RUN') 'Preview lab did not map to NOT_RUN.'
    Assert ((Get-LabTerminalStatus -Failure 'ordinary failure' -Preview $false) -eq 'FAIL') 'Ordinary failure did not map to FAIL.'
    Assert ((Get-LabTerminalStatus -Failure 'MANUAL_RECOVERY_REQUIRED: cleanup incomplete' -Preview $false) -eq 'MANUAL_RECOVERY_REQUIRED') 'Cleanup failure lost manual-recovery severity.'
}
Check 'lab cleanup record requires exact identities and PASS evidence' {
    $run=Join-Path $OutputDirectory 'cleanup-record-fixture'
    [IO.Directory]::CreateDirectory($run)|Out-Null
    $control=@{
        runId=('a'*32)
        switchName='CodexLab-'+('a'*12)
        switchId=[guid]::NewGuid().ToString()
        adapterGuid=[guid]::NewGuid().ToString()
        ipv4='192.0.2.241'
        ipv6='fd42:6364:786c::241'
    }
    $record=@{
        status='PASS'
        runId=$control.runId
        switchId=$control.switchId
        adapterGuid=$control.adapterGuid
        addressesAbsent=$true
    }
    $path=Join-Path $run 'cleanup.json'
    [IO.File]::WriteAllText($path,($record|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    Assert (Test-LabCleanupRecord -RunDirectory $run -Control $control) 'Exact cleanup record rejected.'
    $record.status='FAIL'
    [IO.File]::WriteAllText($path,($record|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    Assert (-not(Test-LabCleanupRecord -RunDirectory $run -Control $control)) 'Failed cleanup record accepted.'
    $record.status='PASS'
    $record.adapterGuid=[guid]::NewGuid().ToString()
    [IO.File]::WriteAllText($path,($record|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    Assert (-not(Test-LabCleanupRecord -RunDirectory $run -Control $control)) 'Cleanup record accepted wrong adapter identity.'
}

Check 'lab consumes Socket status without a success property or network access' {
    $pass=[pscustomobject]@{status='PASS';connectAttempted=$true}
    $negative=[pscustomobject]@{status='FAIL';connectAttempted=$false;failedStage='bind';nativeError=10049}
    Assert (Test-LabSocketAcceptance -Result $pass -ExpectedSuccess $true) 'PASS Socket result was not accepted.'
    Assert (-not(Test-LabSocketAcceptance -Result $negative -ExpectedSuccess $true)) 'FAIL passed positive acceptance.'
    Assert (Test-LabSocketAcceptance -Result $negative -ExpectedSuccess $false -AddressAbsent $true) 'Negative bind evidence rejected.'
    Assert (-not(Test-LabSocketAcceptance -Result $negative -ExpectedSuccess $false -AddressAbsent $false)) 'Address presence ignored.'
    $negative.status='BLOCKED'
    Assert (-not(Test-LabSocketAcceptance -Result $negative -ExpectedSuccess $false -AddressAbsent $true)) 'BLOCKED promoted to expected negative.'
}
Check 'journal rejects all top-level recovery and terminal evidence tampering' {
    $fixture=New-ApprovedTestTransaction
    $applying=Move-NetworkTransactionJournal -Journal $fixture.approved -NextState APPLYING -Now $fixture.now.AddMinutes(2)
    foreach($field in @('desiredAfterHash','token','issuedAt','expiresAt','validationIds','unrestoredResourceIds','failureReason')){
        $tampered=Copy-Value $applying
        switch($field){
            desiredAfterHash {$tampered.desiredAfterHash='d'*64}
            token {$tampered.fencing.token='e'*32}
            issuedAt {$tampered.fencing.issuedAt=$fixture.now.AddSeconds(-1).ToString('o')}
            expiresAt {$tampered.fencing.expiresAt=$fixture.now.AddHours(1).ToString('o')}
            validationIds {$tampered.validationIds=@("ValidationResult-$([guid]::NewGuid())")}
            unrestoredResourceIds {$tampered.unrestoredResourceIds=@('fabricated-resource')}
            failureReason {$tampered.failureReason='Fabricated terminal evidence.'}
        }
        Reject {Assert-NetworkTransactionJournalIntegrity -Journal $tampered}
        Reject {Get-NetworkRecoveryDecision -Journal $tampered -CurrentStateHash ('d'*64)}
    }
    $tampered=Copy-Value $fixture.approved
    $tampered.desiredAfterHash='f'*64
    Reject {Assert-NetworkTransactionApproval -Journal $tampered -ChangeSet $fixture.changeSet}
    foreach($field in @('token','issuedAt','expiresAt')){
        $tampered=Copy-Value $fixture.approved
        if($field -eq 'token'){$tampered.fencing.token='e'*32}else{$tampered.fencing[$field]=$fixture.now.AddHours(2).ToString('o')}
        Reject {Assert-NetworkTransactionApproval -Journal $tampered}
    }
    Reject {Get-NetworkRecoveryDecision -Journal $applying -CurrentStateHash ('d'*64) -DesiredStateHash ('d'*64)}
    $planned=New-NetworkTransactionJournal -ChangeSet $fixture.changeSet -Owner windows -Now $fixture.now -FencingExpiresAt $fixture.now.AddMinutes(30)
    $planned.validationIds=@("ValidationResult-$([guid]::NewGuid())")
    Reject {Approve-NetworkTransactionJournal -Journal $planned -ChangeSet $fixture.changeSet -AuthorizationScope 'fixture' -Principal 'fixture' -ExpiresAt $fixture.now.AddMinutes(3) -Now $fixture.now.AddMinutes(1)}
}
Check 'transaction times and terminal combinations reject before construction' {
    $fixture=New-ApprovedTestTransaction
    Reject {Move-NetworkTransactionJournal -Journal $fixture.approved -NextState APPLYING -Now $fixture.now.AddSeconds(-1)}
    $applying=Move-NetworkTransactionJournal -Journal $fixture.approved -NextState APPLYING -Now $fixture.now.AddMinutes(2)
    $validating=Move-NetworkTransactionJournal -Journal $applying -NextState VALIDATING -Now $fixture.now.AddMinutes(3)
    $vid="ValidationResult-$([guid]::NewGuid())"
    Reject {Move-NetworkTransactionJournal -Journal $validating -NextState COMMITTED -Now $fixture.now.AddMinutes(4) -ValidationIds @($vid) -UnrestoredResourceIds @('adapter-1')}
    $committed=Move-NetworkTransactionJournal -Journal $validating -NextState COMMITTED -Now $fixture.now.AddMinutes(4) -ValidationIds @($vid)
    $committed.unrestoredResourceIds=@('adapter-1')
    Reject {Test-NetworkContract -Type TransactionJournal -Object $committed -SkillRoot $root}
    $args=@{Journal=$fixture.approved;SnapshotId="SnapshotManifest-$([guid]::NewGuid())";Feasibility=@{status='fixture'}}
    Reject {New-NetworkRollbackResult @args -FinalState ROLLBACK_FAILED}
    Reject {New-NetworkRollbackResult @args -FinalState MANUAL_RECOVERY_REQUIRED}
    Reject {New-NetworkRollbackResult @args -FinalState MANUAL_RECOVERY_REQUIRED -ManualSteps @(' ')}
    $manual=New-NetworkRollbackResult @args -FinalState MANUAL_RECOVERY_REQUIRED -ManualSteps @('Inspect exact adapter identity and restore through a trusted console.')
    Test-NetworkContract -Type RollbackResult -Object $manual -SkillRoot $root
    $manual.manualSteps=@()
    Reject {Test-NetworkContract -Type RollbackResult -Object $manual -SkillRoot $root}
    $manual.finalState='ROLLBACK_FAILED'
    Reject {Test-NetworkContract -Type RollbackResult -Object $manual -SkillRoot $root}
}
Check 'controller decision rejects exited process PID reuse port takeover and wrong tuple' {
    $client=[Net.IPEndPoint]::new([Net.IPAddress]::Loopback,41001)
    $server=[Net.IPEndPoint]::new([Net.IPAddress]::Loopback,41002)
    $conn=@{OwningProcess=700;State='Established';LocalAddress='127.0.0.1';LocalPort=41002;RemoteAddress='127.0.0.1';RemotePort=41001}
    $args=@{ExpectedProcessId=700;ExpectedStartTicks=1000;CurrentProcessId=700;CurrentStartTicks=1000;ProcessAlive=$true;ClientEndpoint=$client;ServerEndpoint=$server;ServerConnections=@($conn)}
    Assert (Test-NetworkControllerConnection @args) 'Exact connected owner rejected.'
    $args.ProcessAlive=$false;Reject {Test-NetworkControllerConnection @args};$args.ProcessAlive=$true
    $args.CurrentStartTicks=2000;Reject {Test-NetworkControllerConnection @args};$args.CurrentStartTicks=1000
    $conn.OwningProcess=701;Reject {Test-NetworkControllerConnection @args};$conn.OwningProcess=700
    $conn.RemotePort=41003;Reject {Test-NetworkControllerConnection @args};$conn.RemotePort=41001
    $conn.State='Listen';Reject {Test-NetworkControllerConnection @args}
    $stream=[IO.MemoryStream]::new()
    $handler=[FlClashNetwork.VerifiedConnection]::CreateHandler($stream)
    try {
        $bound=$handler.ConnectCallback.Invoke($null,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
        Assert ([object]::ReferenceEquals($bound,$stream)) 'Handler replaced the verified stream.'
        Reject {$handler.ConnectCallback.Invoke($null,[Threading.CancellationToken]::None).GetAwaiter().GetResult()}
        Assert (-not $handler.UseProxy -and -not $handler.AllowAutoRedirect) 'Bound handler permits redirect/proxy.'
    } finally {$handler.Dispose();$stream.Dispose()}
}
Check 'all mutation entrypoints reject switch-only invocation before state writes' {
    $run=Join-Path $OutputDirectory 'direct-lab-gate-must-not-exist'
    foreach($phrase in @($null,'wrong-case-phrase')){
        $result=& (Join-Path $root 'scripts/lab/Invoke-Lab.ps1') -RunDirectory $run -ConfirmLabMutation -AllowMutation -LabConfirmation $phrase
        Assert ($result.status -eq 'BLOCKED' -and $result.reason -like '*exact*phrase*') 'Direct engine bypassed phrase gate.'
    }
    $worker=(& (Join-Path $root 'scripts/lab/Interrupt-Lab.ps1') -RunDirectory $run -AllowMutation)|ConvertFrom-Json
    $watch=(& (Join-Path $root 'scripts/lab/Watch-Lab.ps1') -RunDirectory $run -ParentProcessId $PID -ParentStartTicks 1 -AllowMutation)|ConvertFrom-Json
    Assert ($worker.status -eq 'BLOCKED' -and $watch.status -eq 'BLOCKED') 'Child switch alone enabled mutation.'
    Assert (-not(Test-Path -LiteralPath $run)) 'Rejected child/engine created state.'
}
Check 'pre-control cleanup query delete and verification failures persist terminal manual recovery' {
    foreach($scenario in @('query','delete','verify')){
        $run=Join-Path $OutputDirectory "early-cleanup-$scenario"
        [IO.Directory]::CreateDirectory($run)|Out-Null
        $created=[pscustomobject]@{Id=[guid]::NewGuid();Name='CodexLab-'+('b'*12);SwitchType='Internal'}
        $cleanup=& {
            param($run,$created,$scenario,$commonPath)
            . $commonPath
            Set-LabMutationAuthorization
            $script:cleanupProbeCount=0
            function Get-VMSwitch {
                if($scenario -eq 'query'){throw 'synthetic query failure'}
                $script:cleanupProbeCount++
                if($scenario -eq 'verify' -and $script:cleanupProbeCount -gt 1){throw 'synthetic verification failure'}
                $created
            }
            function Get-VM {}
            function Get-VMNetworkAdapter {}
            function Remove-VMSwitch {param([Parameter(ValueFromPipeline)]$InputObject,[switch]$Force,[switch]$Confirm) if($scenario -eq 'delete'){throw 'synthetic delete failure'}}
            Invoke-LabCleanup -RunDirectory $run -Created $created -Control $null
        } $run $created $scenario (Join-Path $root 'scripts/lab/Lab.Common.ps1')
        Assert (-not $cleanup.cleanupVerified -and $cleanup.failure -like 'MANUAL_RECOVERY_REQUIRED:*') 'Cleanup failure escaped its boundary.'
        Assert ($cleanup.failure -like '*synthetic*failure*') 'Cleanup mock did not reach the intended failing operation.'
        Write-LabTerminalRecords -RunDirectory $run -Status (Get-LabTerminalStatus -Failure $cleanup.failure -Preview $false) -Failure $cleanup.failure -CleanupVerified $cleanup.cleanupVerified
        foreach($name in @('cleanup-error.json','done.json','result.json')){
            $record=Get-Content -LiteralPath (Join-Path $run $name) -Raw|ConvertFrom-Json
            Assert ($record.status -eq 'MANUAL_RECOVERY_REQUIRED') "Missing terminal evidence in $name."
        }
    }
}
Check 'watchdog covers creation before control and preserves uncertain creation for manual recovery' {
    $run=Join-Path $OutputDirectory 'creation-without-guid'
    [IO.Directory]::CreateDirectory($run)|Out-Null
    Write-LabJson (Join-Path $run 'creation-intent.json') @{runId=('b'*32);switchName='CodexLab-'+('b'*12)}
    $cleanup=& {param($run,$commonPath) . $commonPath;Set-LabMutationAuthorization;Invoke-LabCleanup -RunDirectory $run -Created $null -Control $null} $run (Join-Path $root 'scripts/lab/Lab.Common.ps1')
    Assert (-not $cleanup.cleanupVerified -and $cleanup.failure -like '*without a durable exact switch identity*') 'Uncertain creation was inferred absent.'
    $source=Get-Content -LiteralPath (Join-Path $root 'scripts/lab/Invoke-Lab.ps1') -Raw
    Assert ($source.IndexOf("'watch-ready.json'") -lt $source.IndexOf('$created=New-VMSwitch')) 'Watchdog starts after first host write.'
}
Check 'usage Lab command contains the fixed mandatory confirmation phrase' {
    $doc=Get-Content -LiteralPath (Join-Path $root 'references/usage.md') -Raw
    Assert ($doc -match '(?m)^& \$entry -Intent lab[^\r\n]*-ConfirmLabMutation[^\r\n]*`\r?\n\s+-LabConfirmation CREATE_AND_REMOVE_ISOLATED_HYPERV_LAB_NETWORK') 'Usage Lab command omits the exact phrase.'
}

Check 'braced NetAdapter GUID strings produce strict canonical control and snapshot identities' {
    $raw='{C75C4CD0-DBB5-4D60-9447-DBA0F0620AF3}'
    $canonical='c75c4cd0-dbb5-4d60-9447-dba0f0620af3'
    $switchId=[guid]::NewGuid()
    $control=New-LabControl -RunId ('c'*32) -SwitchId $switchId -AdapterGuid $raw
    Assert ($control.adapterGuid -ceq $canonical -and $control.switchId -ceq $switchId.ToString('D')) 'Control serialized a braced or noncanonical GUID.'
    $addresses=@(
        @{IPAddress='192.0.2.241';PrefixLength=32;SkipAsSource=$true;PolicyStore='ActiveStore'},
        @{IPAddress='fd42:6364:786c::241';PrefixLength=128;SkipAsSource=$true;PolicyStore='ActiveStore'}
    )
    $snapshot=New-LabAddressSnapshot -Control $control -Addresses $addresses
    $roundTrip=ConvertFrom-NetworkJson ($snapshot|ConvertTo-Json -Depth 8)
    Assert ($roundTrip.adapterGuid -ceq $canonical -and $roundTrip.adapterGuid -ceq $control.adapterGuid) 'Snapshot changed the exact control identity format.'
    $schema=Join-Path $root 'schemas/LabAddressSnapshot.schema.json'
    Assert (Test-Json -Json ($snapshot|ConvertTo-Json -Depth 8) -SchemaFile $schema -ErrorAction SilentlyContinue) 'Canonical production snapshot was rejected.'
    $roundTrip.adapterGuid=$raw
    Assert (-not(Test-Json -Json ($roundTrip|ConvertTo-Json -Depth 8) -SchemaFile $schema -ErrorAction SilentlyContinue)) 'Schema accepted a braced GUID.'
    $identity=& {
        param($commonPath,$control,$raw,$switchId)
        . $commonPath
        function Get-LabControl {param($RunDirectory) $control}
        function Get-VMSwitch {[pscustomobject]@{Id=$switchId;Name=$control.switchName;SwitchType='Internal'}}
        function Get-NetAdapter {[pscustomobject]@{InterfaceGuid=$raw;MacAddress='00-11-22-33-44-55';ifIndex=999}}
        function Get-VMNetworkAdapter {[pscustomobject]@{SwitchId=$switchId;MacAddress='001122334455'}}
        Get-LabIdentity 'synthetic-run-no-filesystem-access'
    } (Join-Path $root 'scripts/lab/Lab.Common.ps1') $control $raw $switchId
    Assert ($identity.adapter.InterfaceGuid -ceq $raw -and $identity.control.adapterGuid -ceq $canonical) 'Ownership lookup rejected the same braced adapter identity.'
    $run=Join-Path $OutputDirectory 'braced-guid-cleanup-record'
    [IO.Directory]::CreateDirectory($run)|Out-Null
    Write-LabJson (Join-Path $run 'cleanup.json') @{status='PASS';runId=$control.runId;switchId=$control.switchId;adapterGuid=$raw;addressesAbsent=$true}
    Assert (Test-LabCleanupRecord -RunDirectory $run -Control $control) 'Cleanup identity comparison lost the same GUID.'
}


Check 'owned Lab restore resolves the production schema and rejects invalid snapshots before address access' {
    $control=New-LabControl -RunId ('d'*32) -SwitchId ([guid]::NewGuid()) -AdapterGuid ([guid]::NewGuid())
    $addresses=@(
        [ordered]@{IPAddress='192.0.2.241';PrefixLength=32;SkipAsSource=$true;PolicyStore='ActiveStore'},
        [ordered]@{IPAddress='fd42:6364:786c::241';PrefixLength=128;SkipAsSource=$true;PolicyStore='ActiveStore'}
    )
    $snapshot=New-LabAddressSnapshot -Control $control -Addresses $addresses
    $run=Join-Path $OutputDirectory 'owned-restore-schema'
    [IO.Directory]::CreateDirectory($run)|Out-Null
    $snapshotPath=Join-Path $run 'lab-address-snapshot.json'
    $probe={
        param($commonPath,$run,$snapshotPath,$trustedHash,$control,$addresses)
        . $commonPath
        Set-LabMutationAuthorization
        $script:LabMutationCount=0
        $script:identityReads=0
        $script:addressReads=0
        $script:unexpectedWrites=0
        # The test workspace may sit below a parent Git worktree; directory policy is a separate gate.
        function Assert-LabRunDirectoryBoundary {
            param($RunDirectory,$SkillRoot)
            [IO.Path]::GetFullPath($RunDirectory)
        }
        function Get-LabIdentity {
            param($RunDirectory)
            $script:identityReads++
            [pscustomobject]@{control=$control;adapter=[pscustomobject]@{ifIndex=999}}
        }
        function Get-NetIPAddress {
            [CmdletBinding()]
            param($InterfaceIndex,$PolicyStore)
            if($InterfaceIndex -ne 999 -or $PolicyStore -ne 'ActiveStore'){throw 'Unexpected address scope.'}
            $script:addressReads++
            $addresses|ForEach-Object {[pscustomobject]$_}
        }
        function New-NetIPAddress { $script:unexpectedWrites++; throw 'Unexpected address mutation.' }
        function Wait-LabAddress { throw 'Unexpected wait after address mutation.' }
        $failure=$null
        try { Restore-LabSnapshot -RunDirectory $run -SnapshotPath $snapshotPath -TrustedHash $trustedHash }
        catch { $failure=$_.Exception.Message }
        @{failure=$failure;identityReads=$script:identityReads;addressReads=$script:addressReads;mutationCount=$script:LabMutationCount;unexpectedWrites=$script:unexpectedWrites}
    }
    $commonPath=Join-Path $root 'scripts/lab/Lab.Common.ps1'
    Write-LabJson $snapshotPath $snapshot
    $trustedHash=(Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash
    $valid=& $probe $commonPath $run $snapshotPath $trustedHash $control $addresses
    Assert ($null -eq $valid.failure) "Valid owned snapshot did not pass the production schema and restore checks: $($valid.failure)"
    Assert ($valid.identityReads -eq 3 -and $valid.addressReads -eq 2) 'Valid snapshot did not reach both current-address checks.'
    Assert ($valid.mutationCount -eq 0 -and $valid.unexpectedWrites -eq 0) 'Already-present addresses triggered mutation.'
    $invalid=Copy-Value $snapshot
    $invalid.kind='InvalidSnapshotKind'
    Write-LabJson $snapshotPath $invalid
    $schemaFailure=& $probe $commonPath $run $snapshotPath ((Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash) $control $addresses
    Assert ($schemaFailure.failure -eq 'Lab snapshot schema validation failed; no mutation permitted.') 'Invalid snapshot was not rejected by the real schema.'
    Assert ($schemaFailure.identityReads -eq 0 -and $schemaFailure.addressReads -eq 0 -and $schemaFailure.unexpectedWrites -eq 0) 'Schema-invalid snapshot reached ownership or address operations.'
    $hashFailure=& $probe $commonPath $run $snapshotPath $trustedHash $control $addresses
    Assert ($hashFailure.failure -eq 'Lab snapshot hash mismatch; no mutation permitted.' -and $hashFailure.identityReads -eq 0 -and $hashFailure.addressReads -eq 0 -and $hashFailure.unexpectedWrites -eq 0) 'Tampered bytes reached schema or resource operations.'
}


function Invoke-TestLabRestoreScenario {
    param([string]$Scenario,[object[]]$CurrentAddresses)
    $control=New-LabControl -RunId ('e'*32) -SwitchId ([guid]::NewGuid()) -AdapterGuid ([guid]::NewGuid())
    $addresses=@(
        [ordered]@{IPAddress='192.0.2.241';PrefixLength=32;SkipAsSource=$true;PolicyStore='ActiveStore'},
        [ordered]@{IPAddress='fd42:6364:786c::241';PrefixLength=128;SkipAsSource=$true;PolicyStore='ActiveStore'}
    )
    $run=Join-Path $OutputDirectory ('restore-preflight-'+$Scenario+'-'+[guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($run)|Out-Null
    $snapshotPath=Join-Path $run 'lab-address-snapshot.json'
    Write-LabJson $snapshotPath (New-LabAddressSnapshot -Control $control -Addresses $addresses)
    $trustedHash=(Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash
    & {
        param($commonPath,$run,$snapshotPath,$trustedHash,$control,$addresses,$scenario,$initial)
        . $commonPath
        Set-LabMutationAuthorization
        $script:LabMutationCount=0
        $script:restoreCurrent=@($initial|ForEach-Object {[pscustomobject]$_})
        $script:restoreEvents=[Collections.Generic.List[string]]::new()
        $script:restoreNew=0;$script:restoreRemove=0;$script:restoreDisable=0
        $script:restoreIdentity=0;$script:restoreReads=0
        function Assert-LabRunDirectoryBoundary {param($RunDirectory,$SkillRoot) [IO.Path]::GetFullPath($RunDirectory)}
        function Get-LabIdentity {
            param($RunDirectory)
            $script:restoreIdentity++
            $owned=Copy-Value $control
            if($scenario -eq 'identity-race' -and $script:restoreIdentity -ge 4){$owned.switchId=[guid]::NewGuid().ToString('D')}
            [pscustomobject]@{control=$owned;adapter=[pscustomobject]@{ifIndex=999}}
        }
        function Get-NetIPAddress {
            [CmdletBinding()]
            param($InterfaceIndex,$PolicyStore)
            if($InterfaceIndex -ne 999 -or $PolicyStore -ne 'ActiveStore'){throw 'Unexpected query scope.'}
            $script:restoreReads++
            $script:restoreEvents.Add('read')
            if($scenario -eq 'address-race' -and $script:restoreReads -eq 3){$script:restoreCurrent+=([pscustomobject]$addresses[0])}
            $script:restoreCurrent
        }
        function New-NetIPAddress {
            [CmdletBinding()]
            param($InterfaceIndex,$IPAddress,$PrefixLength,$SkipAsSource,$PolicyStore)
            $script:restoreNew++
            $script:restoreEvents.Add('new:'+$IPAddress)
            if($InterfaceIndex -ne 999 -or $IPAddress -notin @($addresses.IPAddress) -or $PolicyStore -ne 'ActiveStore' -or $SkipAsSource -ne $true){throw 'Unexpected write scope.'}
            if($scenario -in @('second-write-fails','compensation-fails') -and $IPAddress -eq $control.ipv6){throw 'synthetic second write failure'}
            $script:restoreCurrent+=[pscustomobject]@{IPAddress=$IPAddress;PrefixLength=$PrefixLength;SkipAsSource=$SkipAsSource;PolicyStore=$PolicyStore}
        }
        function Wait-LabAddress {param($InterfaceIndex,$Address) if($scenario -eq 'wait-fails'){throw 'synthetic wait failure'}}
        function Remove-NetIPAddress {
            [CmdletBinding()]
            param([Parameter(ValueFromPipeline)]$InputObject,[switch]$Confirm)
            process {
                $script:restoreRemove++
                $script:restoreEvents.Add('remove:'+$InputObject.IPAddress)
                if($scenario -eq 'compensation-fails'){throw 'synthetic compensation failure'}
                if($InputObject.IPAddress -notin @($addresses.IPAddress)){throw 'Unexpected removal scope.'}
                $script:restoreCurrent=@($script:restoreCurrent|Where-Object IPAddress -ne $InputObject.IPAddress)
            }
        }
        function Disable-NetAdapter {$script:restoreDisable++;throw 'Unexpected adapter disable.'}
        function Remove-NetAdapter {$script:restoreDisable++;throw 'Unexpected adapter removal.'}
        function Remove-VMSwitch {$script:restoreDisable++;throw 'Unexpected switch removal.'}
        $failure=$null
        try {Restore-LabSnapshot -RunDirectory $run -SnapshotPath $snapshotPath -TrustedHash $trustedHash}
        catch {$failure=$_.Exception.Message}
        @{failure=$failure;newCalls=$script:restoreNew;removeCalls=$script:restoreRemove;disableCalls=$script:restoreDisable;mutationCount=$script:LabMutationCount;events=@($script:restoreEvents);remaining=@($script:restoreCurrent|ForEach-Object IPAddress)}
    } (Join-Path $root 'scripts/lab/Lab.Common.ps1') $run $snapshotPath $trustedHash $control $addresses $Scenario $CurrentAddresses
}

Check 'Lab restore preflights both addresses and rejects missing IPv4 plus invalid IPv6 with zero mutations' {
    foreach($case in @('prefix','duplicate','skip','store','invalid-type','extra-address','invalid-address')){
        $ipv6=[ordered]@{IPAddress='fd42:6364:786c::241';PrefixLength=128;SkipAsSource=$true;PolicyStore='ActiveStore'}
        switch($case){
            prefix {$ipv6.PrefixLength=64}
            duplicate {}
            skip {$ipv6.SkipAsSource=$false}
            store {$ipv6.PolicyStore='PersistentStore'}
            invalid-type {$ipv6.SkipAsSource='true'}
            extra-address {$ipv6.IPAddress='fd42:6364:786c::242'}
            invalid-address {$ipv6.IPAddress='not-an-ip'}
        }
        $current=@($ipv6)
        if($case -eq 'duplicate'){$current+=Copy-Value $ipv6}
        $result=Invoke-TestLabRestoreScenario -Scenario $case -CurrentAddresses $current
        $expectedFailure=switch($case){
            extra-address {'Unexpected lab address outside snapshot scope.'}
            invalid-address {'*Parse*'}
            default {'Existing lab address drift; refusing overwrite.'}
        }
        Assert ($result.failure -like $expectedFailure) "IPv6 $case failed outside the intended preflight check: $($result.failure)"
        Assert ($result.newCalls -eq 0 -and $result.removeCalls -eq 0 -and $result.disableCalls -eq 0 -and $result.mutationCount -eq 0) "IPv6 $case rejected after a mutation."
    }
}
Check 'Lab restore accepts ActiveStore query objects without a PolicyStore member' {
    $current=@(
        [ordered]@{IPAddress='192.0.2.241';PrefixLength=32;SkipAsSource=$true},
        [ordered]@{IPAddress='fd42:6364:786c::241';PrefixLength=128;SkipAsSource=$true}
    )
    $result=Invoke-TestLabRestoreScenario -Scenario 'missing-policy-store' -CurrentAddresses $current
    Assert ($null -eq $result.failure) "ActiveStore objects without PolicyStore failed restore: $($result.failure)"
    Assert ($result.newCalls -eq 0 -and $result.removeCalls -eq 0 -and $result.disableCalls -eq 0 -and $result.mutationCount -eq 0) 'Property-absent ActiveStore objects triggered mutation.'
    Assert ($result.remaining.Count -eq 2) 'Property-absent ActiveStore objects changed the observed address set.'
}
Check 'Lab restore rechecks missing address and exact ownership immediately before first write' {
    $ipv6=[ordered]@{IPAddress='fd42:6364:786c::241';PrefixLength=128;SkipAsSource=$true;PolicyStore='ActiveStore'}
    foreach($case in @('address-race','identity-race')){
        $result=Invoke-TestLabRestoreScenario -Scenario $case -CurrentAddresses @($ipv6)
        Assert ($result.failure -like '*changed*') "$case did not refuse changed state."
        Assert ($result.newCalls -eq 0 -and $result.removeCalls -eq 0 -and $result.disableCalls -eq 0 -and $result.mutationCount -eq 0) "$case reached a mutation."
    }
}
Check 'Lab restore adds only after complete preflight and compensates its own additions on failure' {
    $success=Invoke-TestLabRestoreScenario -Scenario 'success' -CurrentAddresses @()
    Assert ($null -eq $success.failure -and $success.newCalls -eq 2 -and $success.removeCalls -eq 0 -and $success.disableCalls -eq 0) 'Valid missing-address restore failed.'
    Assert (($success.events[0..2] -join ',') -eq 'read,read,read' -and $success.events[3] -eq 'new:192.0.2.241') 'Write occurred before complete preflight and fresh read.'
    foreach($case in @('second-write-fails','wait-fails')){
        $result=Invoke-TestLabRestoreScenario -Scenario $case -CurrentAddresses @()
        Assert ($result.failure -like 'synthetic*failure' -and $result.removeCalls -eq 1 -and $result.remaining.Count -eq 0 -and $result.disableCalls -eq 0) "$case left an addition or removed unrelated resources."
        Assert ($result.events[-1] -eq 'remove:192.0.2.241') 'Compensation did not remove exactly this call addition.'
    }
    $manual=Invoke-TestLabRestoreScenario -Scenario 'compensation-fails' -CurrentAddresses @()
    Assert ($manual.failure -like 'MANUAL_RECOVERY_REQUIRED:*synthetic compensation failure*' -and $manual.removeCalls -eq 1 -and $manual.remaining.Count -eq 1 -and $manual.disableCalls -eq 0) 'Compensation uncertainty was not surfaced for manual recovery.'
}

$summary=[ordered]@{passed=@($results|Where-Object status -eq PASS).Count;failed=@($results|Where-Object status -eq FAIL).Count;kind='synthetic logic/contract/storage tests; not host network repair validation';tests=@($results)}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'test-results.json'),($summary|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
$summary|ConvertTo-Json -Depth 8
if($summary.failed){exit 1}
