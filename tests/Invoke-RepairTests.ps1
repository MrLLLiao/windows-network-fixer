#Requires -Version 7.4
[CmdletBinding()]
param([string]$OutputDirectory=(Join-Path ([IO.Path]::GetTempPath()) "network-repair-tests-$([guid]::NewGuid())"))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
foreach($module in @('common/Core.psm1','state/State.psm1','transactions/Transactions.psm1','repair/Repair.psm1','audit/Audit.psm1','validation/PathProbe.psm1')){
    Import-Module (Join-Path $root "scripts/$module") -Force -Global -DisableNameChecking
}
[IO.Directory]::CreateDirectory($OutputDirectory)|Out-Null
$results=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[scriptblock]$Body){
    try{& $Body|Out-Null;$results.Add(@{name=$Name;status='PASS';reason=$null})}
    catch{$results.Add(@{name=$Name;status='FAIL';reason=$_.Exception.Message})}
}
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Reject([scriptblock]$Body){$caught=$false;try{& $Body|Out-Null}catch{$caught=$true};Assert $caught 'Expected rejection.'}
function Copy-Value($Value){ConvertFrom-NetworkJson (ConvertTo-Json -InputObject $Value -Depth 50)}
function New-Request {
    @{
        kind='RouteMetric'
        target=@{interfaceGuid='11111111-1111-1111-1111-111111111111';family='IPv4';destinationPrefix='0.0.0.0/0';nextHop='192.0.2.1'}
        desired=@{routeMetric=50}
    }
}
$repairModule=Get-Module Repair
& $repairModule {
    $script:realRead=(Get-Command Get-NetworkRepairState).ScriptBlock
    $script:realWrite=(Get-Command Set-NetworkRepairState).ScriptBlock
    $script:realEffectiveFirewall=(Get-Command Test-NetworkRepairEffectiveFirewall).ScriptBlock
    $script:fakeState=@{present=$true;routeMetric=10}
    $script:fakeWrites=0
    $script:fakeReads=0
    $script:mode='normal'
    function script:Get-NetworkRepairIdentity {@{machine='test-machine';principal='test-user'}}
    function script:Test-NetworkAdministratorToken {$true}
    function script:Get-NetworkRepairState {
        param($Request,$RuleName)
        $script:fakeReads++
        if($script:mode -eq 'prewrite-drift' -and $script:fakeReads -ge 3){return @{present=$true;routeMetric=99}}
        if($script:mode -eq 'prewrite-desired' -and $script:fakeReads -ge 3){return @{present=$true;routeMetric=50}}
        if($script:mode -eq 'rollback-drift' -and $script:fakeWrites -ge 1){return @{present=$true;routeMetric=99}}
        Copy-NetworkRepairValue $script:fakeState
    }
    function script:Set-NetworkRepairState {
        param($Request,$State,$RuleName)
        $script:fakeWrites++
        if($script:mode -eq 'fail-before-write'){throw 'Synthetic provider failure.'}
        $script:fakeState=Copy-NetworkRepairValue $State
        if($script:mode -in @('write-then-throw','rollback-drift','rollback-failure') -and $script:fakeWrites -eq 1){throw 'Synthetic lost acknowledgement.'}
        if($script:mode -eq 'rollback-failure' -and $script:fakeWrites -gt 1){throw 'Synthetic rollback failure.'}
    }
    function script:Initialize-NetworkRepairDirectory {
        param($Path)
        [IO.Directory]::CreateDirectory($Path)|Out-Null
        $Path
    }
    function script:Test-NetworkRepairEffectiveFirewall {param($Plan)}
}
function Reset-Scenario([string]$Name,[string]$Mode='normal'){
    $directory=Join-Path $OutputDirectory $Name
    & $repairModule {
        param($Directory,$Mode)
        $script:testRoot=$Directory
        $script:fakeState=@{present=$true;routeMetric=10}
        $script:fakeWrites=0;$script:fakeReads=0;$script:mode=$Mode
        function script:Get-NetworkProductionRepairRoot {$script:testRoot}
    } $directory $Mode
}
function Save-Plan($Plan,[string]$Name){
    $file=Join-Path $OutputDirectory "$Name.json"
    Write-NetworkJson $file $Plan
    $file
}
Check 'Request rejects unknown operation, fields and ambiguous prefix' {
    foreach($change in @('operation','field','prefix','family','metric')){
        $request=New-Request
        switch($change){
            operation{$request.kind='ShellCommand'}
            field{$request.target.command='netsh int ip reset'}
            prefix{$request.target.destinationPrefix='192.0.2.7/24'}
            family{$request.target.family='IPv6'}
            metric{$request.desired.routeMetric='50'}
        }
        Reject {Assert-NetworkRepairRequest $request}
    }
}
Check 'Plan binds host, user, before, desired and expiration' {
    Reset-Scenario 'plan-binding'
    $plan=New-NetworkRepairPlan (New-Request)
    Assert-NetworkRepairPlan $plan $plan.planHash
    foreach($field in @('before','desired','identity','request')){
        $copy=Copy-Value $plan
        switch($field){
            before{$copy.before.routeMetric=999}
            desired{$copy.desired.routeMetric=999}
            identity{$copy.identity.machine='other'}
            request{$copy.request.target.nextHop='192.0.2.9'}
        }
        Reject {Assert-NetworkRepairPlan $copy $plan.planHash}
    }
    $expired=Copy-Value $plan
    $expired.expiresAt=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
    $expired.planHash='';$expired.planHash=Get-NetworkRepairDigest $expired
    Reject {Assert-NetworkRepairPlan $expired $expired.planHash}
}
Check 'Digest is independent of dictionary insertion order' {
    Assert ((Get-NetworkRepairDigest @{a=1;b=2}) -ceq (Get-NetworkRepairDigest ([ordered]@{b=2;a=1}))) 'Canonical hash is order sensitive.'
}
Check 'WhatIf has zero provider writes and creates no transaction root' {
    Reset-Scenario 'whatif'
    $plan=New-NetworkRepairPlan (New-Request)
    $path=Save-Plan $plan 'whatif-plan'
    $result=Invoke-NetworkProductionRepair -PlanPath $path -ApprovedPlanHash $plan.planHash -WhatIf
    Assert ($result.status -eq 'NOT_RUN' -and -not(Test-Path -LiteralPath (Join-Path $OutputDirectory 'whatif'))) 'WhatIf wrote state.'
    Assert ((& $repairModule {$script:fakeWrites}) -eq 0) 'WhatIf wrote provider.'
}
Check 'Apply commits only after readback; replay is rejected; rollback restores before' {
    Reset-Scenario 'happy'
    $plan=New-NetworkRepairPlan (New-Request)
    $path=Save-Plan $plan 'happy-plan'
    $result=Invoke-NetworkProductionRepair $path $plan.planHash
    Assert ($result.status -eq 'COMMITTED') 'Apply did not commit.'
    Assert ((& $repairModule {$script:fakeWrites}) -eq 1) 'Unexpected write count.'
    Reject {Invoke-NetworkProductionRepair $path $plan.planHash}
    $status=Invoke-NetworkProductionRepair $path $plan.planHash -Intent repair-status
    Assert ($status.equalsDesired -and -not $status.safeToReplay) 'Status did not independently compare.'
    $rollback=Invoke-NetworkProductionRepair $path $plan.planHash -Intent rollback
    Assert ($rollback.status -eq 'ROLLED_BACK') 'Rollback did not converge.'
    Assert ((& $repairModule {$script:fakeState.routeMetric}) -eq 10) 'Before value was not restored.'
    Reject {Invoke-NetworkProductionRepair $path $plan.planHash -Intent rollback}
}
Check 'A later transaction prevents rolling back an older committed plan' {
    Reset-Scenario 'later-transaction'
    $first=New-NetworkRepairPlan (New-Request)
    $firstPath=Save-Plan $first 'later-first'
    Invoke-NetworkProductionRepair $firstPath $first.planHash | Out-Null
    $secondRequest=New-Request;$secondRequest.desired.routeMetric=70
    $second=New-NetworkRepairPlan $secondRequest
    Invoke-NetworkProductionRepair (Save-Plan $second 'later-second') $second.planHash | Out-Null
    Reject {Invoke-NetworkProductionRepair $firstPath $first.planHash -Intent rollback}
    Assert ((& $repairModule {$script:fakeState.routeMetric}) -eq 70) 'Older rollback overwrote a later transaction.'
}
Check 'Route decision refuses create over external route and refuses overwrite of restore' {
    $request=New-Request
    & $repairModule {
        param($Request)
        $request=Copy-NetworkRepairValue $Request
        function Reject([scriptblock]$Body){$caught=$false;try{& $Body|Out-Null}catch{$caught=$true};if(-not $caught){throw 'Expected rejection.'}}
        function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
        $request.kind='RouteAdd'
        Reject {Get-NetworkRepairRouteDecision $request @{present=$true;routeMetric=50} 1}
        $request.kind='RouteRemove'
        Reject {Get-NetworkRepairRouteDecision $request @{present=$true;routeMetric=10} 1}
        Assert ((Get-NetworkRepairRouteDecision $request @{present=$false;routeMetric=$null} 1) -eq 'Remove') 'RouteRemove apply did not select remove.'
        Assert ((Get-NetworkRepairRouteDecision $request @{present=$true;routeMetric=10} 0) -eq 'Create') 'RouteRemove rollback did not select create.'
    } $request
}
Check 'Firewall address block accepts one IP and refuses Any or CIDR scope' {
    $request=@{kind='FirewallBlockAddress';target=@{direction='Inbound';remoteAddress='192.0.2.9'};desired=@{blocked=$true}}
    Assert-NetworkRepairRequest $request
    foreach($address in @('Any','0.0.0.0','127.0.0.1','192.0.2.0/24')){
        $copy=Copy-Value $request;$copy.target.remoteAddress=$address
        Reject {Assert-NetworkRepairRequest $copy}
    }
}
Check 'Lost acknowledgement rolls back only the observed desired state' {
    Reset-Scenario 'lost-ack' 'write-then-throw'
    $plan=New-NetworkRepairPlan (New-Request)
    $result=Invoke-NetworkProductionRepair (Save-Plan $plan 'lost-ack-plan') $plan.planHash
    Assert ($result.status -eq 'ROLLED_BACK' -and -not $result.applySucceeded) 'Lost acknowledgement was misclassified.'
    Assert ((& $repairModule {$script:fakeWrites}) -eq 2) 'Expected one apply and one inverse.'
}
Check 'Provider failure before mutation settles without an inverse write' {
    Reset-Scenario 'before-failure' 'fail-before-write'
    $plan=New-NetworkRepairPlan (New-Request)
    $result=Invoke-NetworkProductionRepair (Save-Plan $plan 'before-failure-plan') $plan.planHash
    Assert ($result.status -eq 'ROLLED_BACK') 'Before failure did not settle.'
    Assert ((& $repairModule {$script:fakeWrites}) -eq 1) 'Blind inverse was attempted.'
}
Check 'Drift between preflight and write causes zero writes and manual review' {
    Reset-Scenario 'drift' 'prewrite-drift'
    $plan=New-NetworkRepairPlan (New-Request)
    $result=Invoke-NetworkProductionRepair (Save-Plan $plan 'drift-plan') $plan.planHash
    Assert ($result.status -eq 'MANUAL_RECOVERY_REQUIRED') 'Drift did not freeze repair.'
    Assert ((& $repairModule {$script:fakeWrites}) -eq 0) 'Write happened after drift.'
}
Check 'External writer reaching desired before apply is never compensated' {
    Reset-Scenario 'drift-to-desired' 'prewrite-desired'
    $plan=New-NetworkRepairPlan (New-Request)
    $result=Invoke-NetworkProductionRepair (Save-Plan $plan 'drift-to-desired-plan') $plan.planHash
    Assert ($result.status -eq 'MANUAL_RECOVERY_REQUIRED') 'External desired state was claimed as a repair.'
    Assert ((& $repairModule {$script:fakeWrites}) -eq 0) 'External desired state was overwritten.'
}
Check 'External drift is never overwritten by compensation and freezes later plans' {
    Reset-Scenario 'external-drift' 'rollback-drift'
    $plan=New-NetworkRepairPlan (New-Request)
    $result=Invoke-NetworkProductionRepair (Save-Plan $plan 'external-drift-plan') $plan.planHash
    Assert ($result.status -eq 'MANUAL_RECOVERY_REQUIRED') 'External state was silently replaced.'
    Assert ((& $repairModule {$script:fakeWrites}) -eq 1) 'Unsafe inverse executed.'
    & $repairModule {$script:mode='normal'}
    $next=New-Request;$next.desired.routeMetric=70
    $nextPlan=New-NetworkRepairPlan $next
    Reject {Invoke-NetworkProductionRepair (Save-Plan $nextPlan 'frozen-plan') $nextPlan.planHash}
}
Check 'Rollback failure preserves a manual recovery terminal record' {
    Reset-Scenario 'inverse-failure' 'rollback-failure'
    $plan=New-NetworkRepairPlan (New-Request)
    $result=Invoke-NetworkProductionRepair (Save-Plan $plan 'inverse-failure-plan') $plan.planHash
    Assert ($result.status -eq 'MANUAL_RECOVERY_REQUIRED') 'Inverse failure was hidden.'
    $events=@(Read-NetworkRepairEvents $result.transactionDirectory $plan)
    Assert ($events[-1].state -eq 'MANUAL_RECOVERY_REQUIRED') 'Missing recovery record.'
}
Check 'Corrupt event and sequence gap reject recovery' {
    Reset-Scenario 'journal'
    $plan=New-NetworkRepairPlan (New-Request)
    $result=Invoke-NetworkProductionRepair (Save-Plan $plan 'journal-plan') $plan.planHash
    $first=Join-Path $result.transactionDirectory '000000.json'
    $event=Read-NetworkRepairJson $first
    $event.state='COMMITTED'
    [IO.File]::WriteAllText($first,(ConvertTo-Json -InputObject $event -Depth 50))
    Reject {Read-NetworkRepairEvents $result.transactionDirectory $plan}
}
Check 'Immutable write-ahead event refuses overwrite' {
    $path=Join-Path $OutputDirectory 'immutable.json'
    Write-NetworkJson $path @{one=1}
    Reject {Write-NetworkJson $path @{two=2}}
}
Check 'Repair resource identities reject reparse and traversal paths' {
    Reject {Assert-NetworkSafePath 'C:\Windows\..\Temp\plan.json'}
    Reject {Assert-NetworkSafePath '\\server\share\plan.json'}
}
Check 'DNS mode forbids mixed family or empty static servers' {
    foreach($servers in @(@(),@('::1'))){
        $request=@{kind='DnsServers';target=@{interfaceGuid='11111111-1111-1111-1111-111111111111';family='IPv4'};desired=@{automatic=$false;servers=$servers}}
        Reject {Assert-NetworkRepairRequest $request}
    }
}
Check 'FirewallProfile refuses disabling and UserProxy refuses machine scope' {
    Reject {Assert-NetworkRepairRequest @{kind='FirewallProfile';target=@{profile='Public'};desired=@{enabled=$false;logBlocked=$true}}}
    Reject {Assert-NetworkRepairRequest @{kind='UserProxy';target=@{scope='LocalMachine'};desired=@{enabled=$false}}}
}
Check 'Path probe keeps literal destination and family validation' {
    Reject {Invoke-NetworkPathProbe -Address 'example.com'}
    Reject {Invoke-NetworkPathProbe -Address '127.0.0.1' -SourceAddress '::1'}
    Reject {Invoke-NetworkPathProbe -Address '127.0.0.1' -TlsName 'bad/name'}
}
Check 'Actual DNS reader preserves an empty automatic configuration' {
    $result=& $repairModule {
        function script:Get-NetworkRepairAdapter {param($Target) [pscustomobject]@{ifIndex=77;InterfaceGuid='11111111-1111-1111-1111-111111111111'}}
        function script:Get-ItemProperty {param($LiteralPath,$ErrorAction) [pscustomobject]@{}}
        $request=@{kind='DnsServers';target=@{interfaceGuid='11111111-1111-1111-1111-111111111111';family='IPv6'};desired=@{automatic=$true;servers=@()}}
        & $script:realRead $request ''
    }
    Assert ($result.automatic -and $result.servers.Count -eq 0) 'Automatic DNS did not survive StrictMode.'
}
Check 'Actual DNS setter passes only the selected family CIM object' {
    $result=& $repairModule {
        $script:dnsCall=$null
        function script:Get-DnsClientServerAddress {param($InterfaceIndex,$AddressFamily,$ErrorAction) [pscustomobject]@{InterfaceIndex=$InterfaceIndex;AddressFamily=$AddressFamily}}
        function script:Set-DnsClientServerAddress {
            param($InputObject,$ServerAddresses,[switch]$ResetServerAddresses,$Confirm,$ErrorAction)
            $script:dnsCall=@{family=$InputObject.AddressFamily;index=$InputObject.InterfaceIndex;reset=[bool]$ResetServerAddresses;servers=@($ServerAddresses)}
        }
        $request=@{kind='DnsServers';target=@{interfaceGuid='11111111-1111-1111-1111-111111111111';family='IPv6'};desired=@{automatic=$true;servers=@()}}
        & $script:realWrite $request @{automatic=$true;servers=@()} ''
        $script:dnsCall
    }
    Assert ($result.family -eq 'IPv6' -and $result.index -eq 77 -and $result.reset) 'DNS setter crossed families or failed to reset.'
}
Check 'Actual RouteAdd setter refuses an externally created route with zero writes' {
    $result=& $repairModule {
        $script:routeCalls=0
        function script:Get-NetRoute {param($InterfaceIndex,$AddressFamily,$PolicyStore,$ErrorAction) [pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='192.0.2.1'}}
        function script:New-NetRoute {$script:routeCalls++}
        function script:Set-NetRoute {$script:routeCalls++}
        $request=@{kind='RouteAdd';target=@{interfaceGuid='11111111-1111-1111-1111-111111111111';family='IPv4';destinationPrefix='0.0.0.0/0';nextHop='192.0.2.1'};desired=@{routeMetric=50}}
        $caught=$false
        try { & $script:realWrite $request @{present=$true;routeMetric=50} '' }
        catch {$caught=$_.Exception.Data.Contains('ManualRecoveryRequired')}
        @{caught=$caught;calls=$script:routeCalls}
    }
    Assert ($result.caught -and $result.calls -eq 0) 'Actual setter overwrote external RouteAdd.'
}
Check 'Actual effective firewall verification rejects disabled active profiles' {
    $caught=& $repairModule {
        function script:Get-NetFirewallRule {param($PolicyStore,$ErrorAction) [pscustomobject]@{Name='CodexNetwork-11111111-1111-1111-1111-111111111111';Action='Block';Enabled='True';PrimaryStatus='OK'}}
        function script:Get-NetConnectionProfile {param($ErrorAction) [pscustomobject]@{NetworkCategory='Public'}}
        function script:Get-NetFirewallProfile {param($Name,$PolicyStore,$ErrorAction) [pscustomobject]@{Name=$Name;Enabled='False'}}
        try { & $script:realEffectiveFirewall @{request=@{kind='FirewallBlockAddress'};ruleName='CodexNetwork-11111111-1111-1111-1111-111111111111'}; $false }
        catch {$true}
    }
    Assert $caught 'Disabled firewall was treated as enforced blocking.'
}
Check 'Firewall full-filter guard rejects external semantic changes' {
    $request=@{kind='FirewallBlockAddress';target=@{direction='Inbound';remoteAddress='192.0.2.9'};desired=@{blocked=$true}}
    $before=@{present=$false}
    $desired=Get-NetworkRepairDesired $request $before 'CodexNetwork-11111111-1111-1111-1111-111111111111'
    $left=Copy-Value $desired;$left.guardHash='a'*64
    $right=Copy-Value $desired;$right.guardHash='b'*64
    Assert (-not(Test-NetworkRepairStateEqual $request $left $right)) 'External firewall semantic change was ignored.'
}
Check 'Public apply without an explicit plan remains zero-write BLOCKED' {
    $result=& (Join-Path $root 'scripts/entrypoints/Invoke-NetworkSkill.ps1') -Intent apply
    Assert ($result.status -eq 'BLOCKED' -and -not $result.networkChanges) 'Missing approval was accepted.'
}
$summary=@{
    passed=@($results|Where-Object status -EQ PASS).Count;failed=@($results|Where-Object status -EQ FAIL).Count
    kind='Synthetic repair coordinator tests; production network providers are mocked. No host network configuration changed.'
    tests=@($results)
}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'repair-test-results.json'),(ConvertTo-Json -InputObject $summary -Depth 10))
$summary|ConvertTo-Json -Depth 10
if($summary.failed){exit 1}
