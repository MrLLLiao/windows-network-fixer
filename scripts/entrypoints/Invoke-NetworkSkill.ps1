#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('inspect','baseline','diagnose','plan','validate','report','snapshot','diff','history','integrity','socket-probe','recovery-check','lab','apply','rollback','audit','watch','watch-events','path-probe','repair-plan','repair-status','process-check')][string]$Intent='diagnose',
    [string]$StateRoot=(Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'CodexNetworkState'),
    [string]$RunId,
    [string]$OtherRunId,
    [switch]$Fixture,
    [switch]$ProbeDns,
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}$')][string]$DnsName='example.com',
    [uri]$ControllerUri,
    [Security.SecureString]$ApiSecret,
    [string]$CoreExecutablePath,
    [string]$ProbeAddress,
    [int]$ProbePort,
    [int]$ProbeInterfaceIndex=-1,
    [string]$ProbeNonce,
    [string]$JournalPath,
    [string]$CurrentStateHash,
    [string]$DesiredStateHash,
    [string]$ChangeSetPath,
    [switch]$ConfirmLabMutation,
    [string]$LabConfirmation,
    [ValidateRange(30,900)][int]$LabTimeoutSeconds=480,
    [string]$RepairRequestPath,
    [string]$RepairPlanPath,
    [string]$ApprovedPlanHash,
    [ValidateRange(2,120)][int]$Samples=6,
    [ValidateRange(100,10000)][int]$IntervalMilliseconds=500,
    [string]$SourceAddress,
    [string]$TlsName,
    [ValidateRange(1,30)][int]$TimeoutSeconds=5,
    [ValidateRange(1,2147483647)][int]$OwnerProcessId=1,
    [ValidateRange(1,120)][int]$DurationSeconds=15
)
$ErrorActionPreference='Stop'
$skillRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach($module in @(
    'common/Core.psm1',
    'discovery/Discovery.psm1',
    'diagnostics/Diagnostics.psm1',
    'state/State.psm1',
    'transactions/Transactions.psm1',
    'validation/Socket.psm1',
    'repair/Repair.psm1',
    'audit/Audit.psm1',
    'audit/Events.psm1',
    'validation/PathProbe.psm1'
)){
    Import-Module (Join-Path $skillRoot "scripts/$module") -Force -Global -DisableNameChecking
}
function Read-NetworkJsonInput {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1,1048576)][int]$MaximumBytes=1048576
    )
    Test-NetworkSafePathSyntax $Path | Out-Null
    $full=[IO.Path]::GetFullPath($Path)
    if(-not(Test-Path -LiteralPath $full -PathType Leaf)){throw 'Input JSON file not found.'}
    $file=Get-Item -LiteralPath $full
    if($file.Length -gt $MaximumBytes){throw 'Input JSON exceeds the size limit.'}
    ConvertFrom-NetworkJson (Get-Content -LiteralPath $full -Raw -Encoding UTF8)
}
function Assert-NetworkLabStateRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SourceRoot
    )
    Test-NetworkSafePathSyntax $Path | Out-Null
    $state=Assert-NetworkSafePath $Path
    $source=[IO.Path]::GetFullPath($SourceRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $sep=[IO.Path]::DirectorySeparatorChar
    if(
        $state.Equals($source,[StringComparison]::OrdinalIgnoreCase) -or
        $state.StartsWith($source+$sep,[StringComparison]::OrdinalIgnoreCase) -or
        $source.StartsWith($state.TrimEnd($sep)+$sep,[StringComparison]::OrdinalIgnoreCase)
    ){throw 'Lab state root and skill source must be disjoint.'}
    $current=$state
    while($current){
        if(Test-Path -LiteralPath $current){
            $item=Get-Item -LiteralPath $current -Force
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse-point lab state paths are forbidden.'}
            if(Test-Path -LiteralPath (Join-Path $current '.git')){throw 'Lab state root must be outside Git worktrees.'}
        }
        $parent=[IO.Path]::GetDirectoryName($current)
        if(-not $parent -or $parent -eq $current){break}
        $current=$parent
    }
    $state
}
function Start-NetworkLabProcess {
    param(
        [Parameter(Mandatory)][string]$StateRoot,
        [ValidateRange(30,900)][int]$TimeoutSeconds,
        [Parameter(Mandatory)][string]$LabConfirmation
    )
    $state=Assert-NetworkLabStateRoot -Path $StateRoot -SourceRoot $skillRoot
    if(-not(Test-Path -LiteralPath $state -PathType Container)){[IO.Directory]::CreateDirectory($state)|Out-Null}
    $runDirectory=Join-Path $state "lab-$([guid]::NewGuid())"
    if(Test-Path -LiteralPath $runDirectory){throw 'Lab run directory already exists.'}
    $processInfo=[Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName=Join-Path $PSHOME 'pwsh.exe'
    if(-not(Test-Path -LiteralPath $processInfo.FileName -PathType Leaf)){throw 'Current PowerShell runtime executable was not found.'}
    $processInfo.UseShellExecute=$false
    $processInfo.CreateNoWindow=$true
    $processInfo.RedirectStandardOutput=$true
    $processInfo.RedirectStandardError=$true
    foreach($argument in @(
        '-NoProfile',
        '-File',
        (Join-Path $skillRoot 'scripts/lab/Invoke-Lab.ps1'),
        '-RunDirectory',
        $runDirectory,
        '-ConfirmLabMutation',
        '-LabConfirmation',
        $LabConfirmation,
        '-AllowMutation'
    )){$processInfo.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::Start($processInfo)
    try{
        $stdoutTask=$process.StandardOutput.ReadToEndAsync()
        $stderrTask=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit($TimeoutSeconds*1000)){
            # Leave the independently started watchdog alive so it can observe parent loss and clean exact IDs.
            try{$process.Kill();$null=$process.WaitForExit(5000)}catch{}
            throw "Lab process exceeded its hard timeout; inspect run directory $runDirectory and manual recovery state."
        }
        $null=$stdoutTask.GetAwaiter().GetResult()
        $null=$stderrTask.GetAwaiter().GetResult()
    }finally{$process.Dispose()}
    $resultPath=Join-Path $runDirectory 'result.json'
    if(-not(Test-Path -LiteralPath $resultPath -PathType Leaf)){
        throw 'Lab process produced no result record.'
    }
    $result=Read-NetworkJsonInput -Path $resultPath
    $result
}
try {
    if($Intent -in @('apply','rollback','repair-status')){
        if($Fixture -or -not $RepairPlanPath -or -not $ApprovedPlanHash){
            [pscustomobject]@{status='BLOCKED';intent=$Intent;reason='Production execution requires a real host repair plan and its exact ApprovedPlanHash.';networkChanges=$false}
            return
        }
        Invoke-NetworkProductionRepair -PlanPath $RepairPlanPath -ApprovedPlanHash $ApprovedPlanHash -Intent $Intent -WhatIf:$WhatIfPreference
        return
    }
    if($Fixture -and $Intent -in @('audit','watch','watch-events','path-probe','repair-plan','process-check')){
        throw 'This intent requires real host evidence; fixture mode is unavailable.'
    }
    switch($Intent){
        'audit' {
            $auditContext=New-NetworkContext
            $auditBundles=Get-NetworkAuditBundles -Context $auditContext -IncludeSecurity
            Save-NetworkAudit -Bundles $auditBundles -Context $auditContext -StateRoot $StateRoot -SkillRoot $skillRoot
            return
        }
        'watch' {
            Invoke-NetworkRaceWatch -StateRoot $StateRoot -SkillRoot $skillRoot -Samples $Samples -IntervalMilliseconds $IntervalMilliseconds
            return
        }
        'watch-events' {
            Invoke-NetworkEventWatch -StateRoot $StateRoot -SkillRoot $skillRoot -DurationSeconds $DurationSeconds
            return
        }
        'path-probe' {
            if(-not $ProbeAddress){throw 'path-probe requires an explicit numeric ProbeAddress.'}
            $port=if($ProbePort){$ProbePort}else{443}
            Invoke-NetworkPathProbe -Address $ProbeAddress -Port $port -SourceAddress $SourceAddress -TlsName $TlsName -TimeoutSeconds $TimeoutSeconds
            return
        }
        'process-check' {
            Get-NetworkProcessEvidence -ProcessId $OwnerProcessId
            return
        }
        'repair-plan' {
            if(-not $RepairRequestPath){throw 'repair-plan requires RepairRequestPath.'}
            $request=Read-NetworkRepairJson $RepairRequestPath
            $repairPlan=New-NetworkRepairPlan -Request $request
            if(-not $PSCmdlet.ShouldProcess($repairPlan.id,'write a repair plan for review')){
                [pscustomobject]@{status='NOT_RUN';planHash=$repairPlan.planHash;plan=$repairPlan;request=$repairPlan.request;before=$repairPlan.before;desired=$repairPlan.desired;expiresAt=$repairPlan.expiresAt;networkChanges=$false}
                return
            }
            $planDirectory=New-NetworkRunDirectory -StateRoot $StateRoot -SkillRoot $skillRoot
            $planFile=Join-Path $planDirectory 'repair-plan.json'
            Write-NetworkJson -Path $planFile -Object $repairPlan
            [pscustomobject]@{status='PLANNED';planPath=$planFile;planHash=$repairPlan.planHash;request=$repairPlan.request;before=$repairPlan.before;desired=$repairPlan.desired;expiresAt=$repairPlan.expiresAt;networkChanges=$false}
            return
        }
        'socket-probe' {
            if($Fixture){throw 'Socket probe cannot run in fixture mode.'}
            if([string]::IsNullOrWhiteSpace($ProbeAddress) -or $ProbePort -lt 1 -or $ProbePort -gt 65535 -or [string]::IsNullOrWhiteSpace($ProbeNonce)){throw 'Socket probe requires ProbeAddress, ProbePort 1-65535 and ProbeNonce.'}
            Invoke-NetworkSocketProbe -Address $ProbeAddress -Port $ProbePort -InterfaceIndex $ProbeInterfaceIndex -Nonce $ProbeNonce
            return
        }
        'recovery-check' {
            if($Fixture){throw 'Recovery check cannot run in fixture mode.'}
            if([string]::IsNullOrWhiteSpace($JournalPath) -or [string]::IsNullOrWhiteSpace($CurrentStateHash)){throw 'Recovery check requires JournalPath and CurrentStateHash.'}
            $journal=Read-NetworkJsonInput -Path $JournalPath
            Test-NetworkContract -Type TransactionJournal -Object $journal -SkillRoot $skillRoot
            if($ChangeSetPath){
                $changeSet=Read-NetworkJsonInput -Path $ChangeSetPath
                Test-NetworkContract -Type ChangeSet -Object $changeSet -SkillRoot $skillRoot
                Assert-NetworkTransactionApproval -Journal $journal -ChangeSet $changeSet
            }
            $decisionArguments=@{
                Journal=$journal
                CurrentStateHash=$CurrentStateHash
            }
            if($DesiredStateHash){$decisionArguments.DesiredStateHash=$DesiredStateHash}
            Get-NetworkRecoveryDecision @decisionArguments
            return
        }
        'lab' {
            if(-not $IsWindows){
                [pscustomobject]@{status='BLOCKED';intent='lab';reason='Windows is required.';networkChanges=$false}
                return
            }
            if(-not (Test-NetworkAdministratorToken)){
                [pscustomobject]@{status='BLOCKED';intent='lab';reason='Administrator PowerShell is required.';networkChanges=$false}
                return
            }
            if(-not(Test-NetworkLabConfirmation -GateOpen ([bool]$ConfirmLabMutation) -Phrase $LabConfirmation)){
                [pscustomobject]@{status='BLOCKED';intent='lab';reason='Explicit -ConfirmLabMutation and the exact -LabConfirmation phrase are required before any lab state or network mutation.';networkChanges=$false}
                return
            }
            if(-not $PSCmdlet.ShouldProcess($StateRoot,'Create and remove one disposable Hyper-V Internal lab and its exact test addresses')){
                [pscustomobject]@{status='NOT_RUN';intent='lab';reason='Lab preview only; no state or network writes were performed.';networkChanges=$false}
                return
            }
            Start-NetworkLabProcess -StateRoot $StateRoot -TimeoutSeconds $LabTimeoutSeconds -LabConfirmation $LabConfirmation
            return
        }
        'history' {Get-NetworkHistory -StateRoot $StateRoot;return}
        'integrity' {Test-NetworkSnapshot -StateRoot $StateRoot -RunId $RunId -SkillRoot $skillRoot;return}
        'diff' {Compare-NetworkRuns -StateRoot $StateRoot -RunId $RunId -OtherRunId $OtherRunId -SkillRoot $skillRoot;return}
    }
    if($Fixture -and ($ProbeDns -or $ControllerUri -or $ApiSecret -or $CoreExecutablePath)){throw 'Fixture mode cannot contact network or accept credentials.'}
    if($ApiSecret -and -not $ControllerUri){throw 'ApiSecret requires an explicitly verified ControllerUri.'}
    if($CoreExecutablePath -and -not $ControllerUri){throw 'CoreExecutablePath requires an explicitly verified ControllerUri.'}
    $context=New-NetworkContext -Synthetic:$Fixture
    if($Fixture){
        $raw=Get-Content -LiteralPath (Join-Path $skillRoot 'tests/fixtures/dual-stack-tun.json') -Raw -Encoding UTF8|ConvertFrom-Json -AsHashtable
        $bundles=[ordered]@{}
        foreach($key in $raw.Keys){$items=$raw[$key];$bundles[$key]=Invoke-NetworkRead -Name "SYNTHETIC fixture $key" -Context $context -Read {$items}}
    }else{
        $bundles=Get-NetworkDiscovery -Context $context -ProbeDns:$ProbeDns -DnsName $DnsName
        if($ControllerUri){
            $api=Get-NetworkController -ControllerUri $ControllerUri -Context $context -ApiSecret $ApiSecret -CoreExecutablePath $CoreExecutablePath
            foreach($key in $api.Keys){$bundles["api$key"]=$api[$key]}
        }
    }
    $baseline=New-NetworkBaseline -Bundles $bundles -Context $context
    $diagnostics=@(Get-NetworkDiagnostics -Baseline $baseline -Context $context)
    $validations=@((New-NetworkValidation -Context $context -EvidenceIds @($baseline.evidenceIds) -Family IPv4),(New-NetworkValidation -Context $context -EvidenceIds @($baseline.evidenceIds) -Family IPv6))
    $proposal=New-NetworkProposal -Baseline $baseline -Diagnostics $diagnostics -Context $context
    $run=New-NetworkRunDirectory -StateRoot $StateRoot -SkillRoot $skillRoot
    Save-NetworkRun -RunDirectory $run -Bundles $bundles -Baseline $baseline -Diagnostics $diagnostics -Validations $validations -Proposal $proposal -SkillRoot $skillRoot
    $snapshot=New-NetworkSnapshot -RunDirectory $run -Context $context -Baseline $baseline -SkillRoot $skillRoot
    [pscustomobject]@{status='PASS';meaning='Observation artifacts written; not a network health or repair verdict.';intent=$Intent;runId=(Split-Path $run -Leaf);runDirectory=$run;report=(Join-Path $run 'report.md');synthetic=[bool]$Fixture;networkChanges=$false;recoverability=$snapshot.recoverability;collectionBlocked=@($bundles.Values|Where-Object {$_.record.collectionStatus -eq 'BLOCKED'}).Count;nativeTests='NOT_RUN'}
}catch{
    # Do not echo arbitrary input or response text into persisted records.
    throw "Network skill stopped: $($_.Exception.Message)"
}
