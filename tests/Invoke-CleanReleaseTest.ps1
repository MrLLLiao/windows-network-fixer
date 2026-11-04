#Requires -Version 7.4
[CmdletBinding()]
param(
    [string]$Revision,
    [string]$OutputDirectory=(Join-Path ([IO.Path]::GetTempPath()) "flclash-clean-release-$([guid]::NewGuid())")
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
$output=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $output){throw 'Clean release test requires a new output directory.'}
[IO.Directory]::CreateDirectory($output)|Out-Null
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Rehash-Manifest([string]$Directory){
    $path=Join-Path $Directory 'snapshot.json'
    $manifest=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
    $manifest.manifestHash=''
    $json=ConvertTo-Json -InputObject $manifest -Depth 50 -Compress
    $manifest.manifestHash=[Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($json))
    ).ToLowerInvariant()
    [IO.File]::WriteAllText(
        $path,
        ($manifest|ConvertTo-Json -Depth 50),
        [Text.UTF8Encoding]::new($false)
    )
}
$releasePaths=@('CHANGELOG.md','SKILL.md','agents','manifests','references','schemas','scripts','tests')
$release=Join-Path $output 'release'
if($Revision){
    $archive=Join-Path $output 'tracked-release.zip'
    & git -C $root archive --format=zip "--output=$archive" $Revision @releasePaths
    if($LASTEXITCODE -ne 0){throw 'Tracked release export failed.'}
    Expand-Archive -LiteralPath $archive -DestinationPath $release
    $exportKind='git archive (tracked content only)'
}elseif((Test-Path -LiteralPath (Join-Path $root '.git')) -and (& git -C $root rev-parse --is-inside-work-tree 2>$null) -eq 'true'){
    # A default run must model a clean checkout: only files tracked for release are exported.
    # The previous filesystem copy masked .gitignore rules that silently excluded source.
    [IO.Directory]::CreateDirectory($release)|Out-Null
    $tracked=@(& git -C $root ls-files -- $releasePaths)
    if($LASTEXITCODE -ne 0){throw 'Tracked release manifest read failed.'}
    foreach($relative in $tracked){
        $sourcePath=Join-Path $root $relative
        if(-not(Test-Path -LiteralPath $sourcePath -PathType Leaf)){throw "Tracked release file is missing from the working tree: $relative"}
        $target=Join-Path $release $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))|Out-Null
        Copy-Item -LiteralPath $sourcePath -Destination $target -ErrorAction Stop
    }
    $exportKind='git tracked-file manifest export; ignored and untracked release files excluded'
}else{
    [IO.Directory]::CreateDirectory($release)|Out-Null
    foreach($path in $releasePaths){
        Copy-Item -LiteralPath (Join-Path $root $path) -Destination (Join-Path $release $path) -Recurse -ErrorAction Stop
    }
    $exportKind='fresh filesystem export, exact release whitelist; no Git commit required'
}
$unexpected=@(Get-ChildItem -LiteralPath $release -Force | Where-Object {
    $_.Name -in @('.git','.w1mer','.graphflow','graphify-out','state')
})
Assert ($unexpected.Count -eq 0) 'Release whitelist exported internal or state content.'
$entry=Join-Path $release 'scripts/entrypoints/Invoke-NetworkSkill.ps1'
$state=Join-Path $output 'observations'
$installDestination=Join-Path $output 'install-target/windows-network-fixer'
$installBackup=Join-Path $output 'install-backups'
$installPreview=& (Join-Path $release 'scripts/install/Install-NetworkSkill.ps1') -Destination $installDestination -BackupRoot $installBackup -WhatIf
Assert ($installPreview.status -eq 'NOT_RUN') 'Clean export installer preview failed.'
Assert (-not(Test-Path -LiteralPath $installDestination)) 'Installer preview wrote to the destination.'
$manifest=Get-Content -LiteralPath (Join-Path $release 'manifests/compatibility.json') -Raw|ConvertFrom-Json
$skill=Get-Content -LiteralPath (Join-Path $release 'SKILL.md') -Raw
Assert (Test-Path -LiteralPath (Join-Path $release 'scripts/state/State.psm1') -PathType Leaf) 'Clean export omitted scripts/state/State.psm1.'
Assert ($manifest.version -eq '1.1.0') 'Clean export version mismatch.'
Assert ($skill -match '(?m)^\s*name:\s*windows-network-fixer\s*$') 'Clean export SKILL name mismatch.'
Assert ($skill -match '(?m)^\s+version:\s*"1\.1\.0"\s*$') 'Clean export SKILL metadata mismatch.'
Assert ($manifest.apply -and $manifest.rollback -and -not $manifest.restoreReadySnapshots) 'Clean export production execution policy mismatch.'
$first=& $entry -Intent plan -Fixture -StateRoot $state
$second=& $entry -Intent snapshot -Fixture -StateRoot $state
Assert ($first.status -eq 'PASS' -and $first.synthetic -and -not $first.networkChanges) 'Clean release fixture failed.'
foreach($run in @($first,$second)){
    $integrity=& $entry -Intent integrity -StateRoot $state -RunId $run.runId
    Assert ($integrity.status -eq 'PASS' -and $integrity.recoverability -eq 'none') 'Clean release integrity failed.'
}
$legacyPath=Join-Path $second.runDirectory 'snapshot.json'
$legacy=Get-Content -LiteralPath $legacyPath -Raw|ConvertFrom-Json
$legacy.producer='flclash-windows-network/0.1.0'
[IO.File]::WriteAllText($legacyPath,($legacy|ConvertTo-Json -Depth 50),[Text.UTF8Encoding]::new($false))
Rehash-Manifest $second.runDirectory
$legacyIntegrity=& $entry -Intent integrity -StateRoot $state -RunId $second.runId
Assert ($legacyIntegrity.status -eq 'PASS') 'Clean export rejected legacy snapshot.'
$differences=@(& $entry -Intent diff -StateRoot $state -RunId $first.runId -OtherRunId $second.runId)
Assert ($differences.Count -eq 12 -and @($differences|Where-Object changed).Count -eq 0) 'Clean release comparison failed.'
$ready=Join-Path $output 'socket-ready.json'
$socketJob=Start-Job -ArgumentList $ready -ScriptBlock {
    param($ReadyPath)
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('127.0.0.1'),0)
    try{
        $listener.Start()
        [IO.File]::WriteAllText($ReadyPath,(@{port=$listener.LocalEndpoint.Port}|ConvertTo-Json))
        $client=$listener.AcceptTcpClient()
        try{
            $stream=$client.GetStream();$buffer=[byte[]]::new(64);$read=$stream.Read($buffer,0,$buffer.Length)
            $stream.Write($buffer,0,$read)
        }finally{$client.Dispose()}
    }finally{$listener.Stop()}
}
try{
    for($i=0;$i -lt 100 -and -not(Test-Path -LiteralPath $ready);$i++){Start-Sleep -Milliseconds 50}
    Assert (Test-Path -LiteralPath $ready) 'Clean release echo listener not ready.'
    $socketPort=[int](Get-Content -LiteralPath $ready -Raw|ConvertFrom-Json).port
    $socket=& $entry -Intent socket-probe -ProbeAddress 127.0.0.1 -ProbePort $socketPort -ProbeNonce 'clean-release-socket-nonce'
}finally{
    Stop-Job -Job $socketJob -ErrorAction SilentlyContinue
    Remove-Job -Job $socketJob -Force -ErrorAction SilentlyContinue
}
Assert ($socket.status -eq 'PASS' -and $socket.nonceMatched -and $socket.connectAttempted) 'Clean release socket probe failed.'
foreach($address in @('192.0.2.254','fd42:6364:786c::254')){
    $negative=& $entry -Intent socket-probe -ProbeAddress $address -ProbePort 1 -ProbeNonce 'clean-release-negative'
    Assert ($negative.status -eq 'FAIL' -and $negative.failedStage -eq 'bind' -and $negative.nativeError -eq 10049 -and -not $negative.connectAttempted) "Clean release negative bind failed for $address."
}
$labState=Join-Path $output 'lab-must-not-exist'
$lab=& $entry -Intent lab -StateRoot $labState
Assert ($lab.status -eq 'BLOCKED' -and -not $lab.networkChanges) 'Clean release lab gate failed.'
Assert (-not(Test-Path -LiteralPath $labState)) 'Unconfirmed clean-release lab created state.'
$blockedState=Join-Path $output 'must-not-exist'
foreach($intent in @('apply','rollback')){
    $blocked=& $entry -Intent $intent -StateRoot $blockedState
    Assert ($blocked.status -eq 'BLOCKED') 'Clean release mutation was not blocked.'
}
Assert (-not(Test-Path -LiteralPath $blockedState)) 'Blocked mutation wrote state.'
$regressionOutput=Join-Path $output 'regression'
& (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File (Join-Path $release 'tests/Invoke-Tests.ps1') -OutputDirectory $regressionOutput
if($LASTEXITCODE -ne 0){throw 'Clean release regression suite failed.'}
$regression=Get-Content -LiteralPath (Join-Path $regressionOutput 'test-results.json') -Raw|ConvertFrom-Json
Assert ($regression.failed -eq 0 -and $regression.passed -ge 60) 'Clean release regression ledger is incomplete.'
$repairOutput=Join-Path $output 'repair-regression'
& (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File (Join-Path $release 'tests/Invoke-RepairTests.ps1') -OutputDirectory $repairOutput
if($LASTEXITCODE -ne 0){throw 'Clean release repair suite failed.'}
$repair=Get-Content -LiteralPath (Join-Path $repairOutput 'repair-test-results.json') -Raw|ConvertFrom-Json
Assert ($repair.failed -eq 0 -and $repair.passed -ge 18) 'Clean release repair ledger is incomplete.'
$result=@{
    status='PASS'
    revision=$Revision
    source=$exportKind
    fixtureRuns=2
    integrity='PASS'
    legacySnapshotCompatibility='PASS'
    diff='PASS'
    sameHostSocket='PASS'
    negativeBindGuards='PASS'
    labGate='PASS'
    installerPreview='PASS'
    regression="$($regression.passed)/$($regression.passed + $regression.failed)"
    repairRegression="$($repair.passed)/$($repair.passed + $repair.failed)"
    mutations='BLOCKED_WITHOUT_PLAN'
    networkChanges=$false
}
[IO.File]::WriteAllText(
    (Join-Path $output 'clean-release-result.json'),
    ($result|ConvertTo-Json),
    [Text.UTF8Encoding]::new($false)
)
$result|ConvertTo-Json
