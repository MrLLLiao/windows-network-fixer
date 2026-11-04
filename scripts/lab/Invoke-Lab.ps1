#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$RunDirectory,
    [switch]$ConfirmLabMutation,
    [string]$LabConfirmation,
    [switch]$AllowMutation
)
. (Join-Path $PSScriptRoot 'Lab.Common.ps1')
$skillRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $AllowMutation -or -not (Test-NetworkLabConfirmation -GateOpen ([bool]$ConfirmLabMutation) -Phrase $LabConfirmation)) {
    [pscustomobject][ordered]@{
        status = 'BLOCKED'
        reason = 'Lab mutation requires both switches and the exact -LabConfirmation phrase.'
        networkChanges = $false
    }
    return
}
if (-not $IsWindows) {
    [pscustomobject][ordered]@{
        status = 'BLOCKED'
        reason = 'Isolated lab requires Windows.'
        networkChanges = $false
    }
    return
}
if (-not (Test-NetworkAdministratorToken)) {
    [pscustomobject][ordered]@{
        status = 'BLOCKED'
        reason = 'Isolated lab requires an administrator PowerShell process.'
        networkChanges = $false
    }
    return
}
try {
    $RunDirectory = Assert-LabRunDirectoryBoundary `
        -RunDirectory $RunDirectory `
        -SkillRoot $skillRoot
} catch {
    [pscustomobject][ordered]@{
        status = 'BLOCKED'
        reason = $_.Exception.Message
        networkChanges = $false
    }
    return
}
Set-LabMutationAuthorization
$script:LabMutationCount=0
$servers=@{};$watch=$null;$created=$null;$control=$null;$productionBefore=$null;$original=@();$preview=$false;$nonce=[guid]::NewGuid().ToString('N');$tests=[Collections.Generic.List[object]]::new();$failed=$null
if(Test-Path -LiteralPath $RunDirectory){throw 'Run directory exists; refusing reuse.'}
[IO.Directory]::CreateDirectory($RunDirectory)|Out-Null
$runId=[guid]::NewGuid().ToString('N');$name='CodexLab-'+$runId.Substring(0,12)
$ip4='192.0.2.241';$ip6='fd42:6364:786c::241'
$pwsh=Join-Path $PSHOME 'pwsh.exe'
if(-not(Test-Path -LiteralPath $pwsh -PathType Leaf)){throw 'Current PowerShell runtime executable was not found.'}
function Start-HiddenLabProcess {
    param([string]$File,[string[]]$Arguments,[switch]$Wait)
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$pwsh;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    foreach($arg in @('-NoProfile','-File',$File)+$Arguments){$info.ArgumentList.Add($arg)}
    $proc=[Diagnostics.Process]::Start($info)
    $ownedStart=$proc.StartTime.ToUniversalTime().Ticks
    if($Wait){if(-not $proc.WaitForExit(20000)){
        $current=Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
        if($current -and $current.StartTime.ToUniversalTime().Ticks -eq $ownedStart){$proc.Kill($true);if(-not $proc.WaitForExit(5000)){throw 'Owned child failed to terminate.'}}
        $proc.Dispose();throw 'Owned lab child timed out and was terminated.'
    }}
    $proc
}
function Get-CriticalAdapterBaseline {
    $adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $defaultInterfaces=@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}|ForEach-Object {$_.InterfaceIndex})
    $selected=@($adapters|Where-Object {
        $identityText="$($_.Name) $($_.InterfaceDescription)"
        $hardwareProperty=$_.PSObject.Properties['HardwareInterface']
        $isPhysical=$(if($hardwareProperty){[bool]$hardwareProperty.Value}else{-not [bool]$_.Virtual})
        $isProductionEgress=($defaultInterfaces -contains $_.ifIndex)
        $isFlClashTun=($identityText -match '(?i)FlClash|Mihomo|Clash|(^|[\s_-])Tun([\s_-]|$)')
        $isPhysical -or $isProductionEgress -or $isFlClashTun
    }|Sort-Object InterfaceGuid -Unique|Sort-Object ifIndex,InterfaceGuid)
    if($selected.Count -eq 0){throw 'No critical production adapters identified.'}
    @($selected|ForEach-Object {
        [ordered]@{
            InterfaceGuid=[guid]::Parse([string]$_.InterfaceGuid).ToString('D')
            ifIndex=[int]$_.ifIndex
            Name=$_.Name
            InterfaceDescription=$_.InterfaceDescription
        }
    })
}
function Get-ProductionState {
    param([object[]]$ExpectedAdapters)
    $allAdapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $currentAdapters=@()
    foreach($expected in $ExpectedAdapters){
        $match=@($allAdapters|Where-Object {[guid]::Parse([string]$_.InterfaceGuid).ToString('D') -eq [guid]::Parse([string]$expected.InterfaceGuid).ToString('D')})
        if($match.Count -eq 0){
            $currentAdapters+=[ordered]@{InterfaceGuid=[guid]::Parse([string]$expected.InterfaceGuid).ToString('D');present=$false}
            continue
        }
        if($match.Count -ne 1){throw ('Duplicate adapter identity: '+$expected.InterfaceGuid)}
        $adapter=$match[0]
        $currentAdapters+=[ordered]@{
            InterfaceGuid=[guid]::Parse([string]$adapter.InterfaceGuid).ToString('D')
            present=$true
            ifIndex=[int]$adapter.ifIndex
            Name=$adapter.Name
            InterfaceDescription=$adapter.InterfaceDescription
        }
    }
    $currentAdapters=@($currentAdapters|Sort-Object InterfaceGuid)
    $criticalInterfaces=@($currentAdapters|Where-Object {$_.present}|ForEach-Object {$_.ifIndex})
    $criticalNames=@($currentAdapters|Where-Object {$_.present}|ForEach-Object {$_.Name})
    $inet=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $proxyHashes=@{}
    foreach($key in @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL','AutoDetect')){
        $property=$inet.PSObject.Properties[$key];$serialized=ConvertTo-Json -InputObject $(if($property){$property.Value}else{$null}) -Compress
        $proxyHashes[$key]=@{present=($null -ne $property);sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($serialized)))}
    }
    $netsh=Join-Path ([Environment]::SystemDirectory) 'netsh.exe'
    if(-not(Test-Path -LiteralPath $netsh -PathType Leaf)){throw 'Windows netsh executable is unavailable.'}
    $winhttp=(& $netsh winhttp show proxy | Out-String);if($LASTEXITCODE -ne 0){throw 'WinHTTP read failed.'}
    [ordered]@{
        criticalAdapters=$currentAdapters
        defaultRoutes=@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}|Sort-Object InterfaceIndex,DestinationPrefix,NextHop|Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
        criticalRoutes=@(Get-NetRoute -ErrorAction Stop|Where-Object {$_.InterfaceIndex -in $criticalInterfaces}|Sort-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore|Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore)
        addresses=@(Get-NetIPAddress -ErrorAction Stop|Where-Object {$_.InterfaceIndex -in $criticalInterfaces}|Sort-Object InterfaceIndex,IPAddress,PrefixLength|Select-Object InterfaceIndex,IPAddress,PrefixLength,PolicyStore)
        dns=@(Get-DnsClientServerAddress -ErrorAction Stop|Where-Object {$_.InterfaceIndex -in $criticalInterfaces}|Sort-Object InterfaceIndex,AddressFamily|Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
        bindings=@(Get-NetAdapterBinding -ComponentID ms_tcpip,ms_tcpip6 -ErrorAction Stop|Where-Object {$_.Name -in $criticalNames}|Sort-Object Name,ComponentID|Select-Object Name,ComponentID,Enabled)
        proxy=$proxyHashes
        winhttpSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($winhttp)))
        flclash=@(Get-Process -Name 'FlClash*' -ErrorAction SilentlyContinue|Sort-Object Id|Select-Object Id,ProcessName,@{Name='StartTimeTicks';Expression={$_.StartTime.ToUniversalTime().Ticks}})
    }
}
function Assert-ProductionStable {
    param([string]$Stage)
    $current=Get-ProductionState $criticalAdapters
    Write-LabJson (Join-Path $RunDirectory ('production-'+$Stage+'.json')) $current
    if(($current|ConvertTo-Json -Depth 8 -Compress) -cne ($productionBefore|ConvertTo-Json -Depth 8 -Compress)){throw ('Production state drift at '+$Stage+'; do not restore production configuration automatically.')}
}
function Test-LabEcho {
    param([string]$Stage,[string]$Address,[int]$Port,[bool]$ExpectedSuccess)
    $x=Get-LabIdentity $RunDirectory
    $path=Join-Path $RunDirectory ($Stage+'.json')
    $proc=Start-HiddenLabProcess -File (Join-Path $PSScriptRoot 'Verify-Lab.ps1') -Arguments @('-Address',$Address,'-Port',"$Port",'-InterfaceIndex',"$($x.adapter.ifIndex)",'-Nonce',$nonce,'-OutputPath',$path) -Wait
    if(-not(Test-Path -LiteralPath $path)){throw 'Independent verifier produced no result.'}
    $result=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    $absent=if($ExpectedSuccess){$false}else{@(Get-LabConfig $RunDirectory|Where-Object {$_.IPAddress -eq $Address}).Count -eq 0}
    $accepted=Test-LabSocketAcceptance -Result $result -ExpectedSuccess $ExpectedSuccess -AddressAbsent $absent
    $test=[ordered]@{id=$Stage;expectedSuccess=$ExpectedSuccess;observedSuccess=($result.status -eq 'PASS');exitCode=$proc.ExitCode;status=$(if($accepted){'PASS'}else{'FAIL'});evidence=[IO.Path]::GetFileName($path)}
    $tests.Add($test);Write-Output ($test|ConvertTo-Json -Compress)
    if($test.status -ne 'PASS'){throw ('Echo acceptance failed: '+$Stage)}
}
function Stop-LabEchoServer {
    param([string]$Family)
    if($servers.ContainsKey($Family)){
        $job=$servers[$Family]
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        $servers.Remove($Family)
    }
}
function Start-LabEchoServer {
    param([string]$Family,[string]$Address)
    Stop-LabEchoServer $Family
    $ready=Join-Path $RunDirectory ($Family+'-server.json')
    if(Test-Path -LiteralPath $ready){Remove-Item -LiteralPath $ready -Force}
    $job=Start-Job -ArgumentList $Address,$ready,$nonce -ScriptBlock {
        param($Address,$Ready,$Expected)
        $ErrorActionPreference='Stop';$listener=$null
        try{
            $ip=[Net.IPAddress]::Parse($Address);$listener=[Net.Sockets.TcpListener]::new($ip,0)
            if($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$listener.Server.DualMode=$false}
            $listener.Start();[IO.File]::WriteAllText($Ready,(@{port=$listener.LocalEndpoint.Port}|ConvertTo-Json))
            $deadline=[DateTime]::UtcNow.AddMinutes(8)
            while([DateTime]::UtcNow -lt $deadline){
                if(-not $listener.Pending()){Start-Sleep -Milliseconds 30;continue}
                $client=$listener.AcceptTcpClient()
                try{
                    $stream=$client.GetStream();$stream.ReadTimeout=3000
                    $buffer=[byte[]]::new([Text.Encoding]::UTF8.GetByteCount($Expected));$n=0
                    while($n -lt $buffer.Length){$read=$stream.Read($buffer,$n,$buffer.Length-$n);if($read -eq 0){break};$n+=$read}
                    if([Text.Encoding]::UTF8.GetString($buffer,0,$n) -ceq $Expected){$stream.Write($buffer,0,$n)}
                }finally{$client.Dispose()}
            }
        }finally{if($listener){$listener.Stop()}}
    }
    $servers[$Family]=$job
    for($i=0;$i -lt 100 -and -not(Test-Path -LiteralPath $ready);$i++){
        if($job.State -eq 'Failed'){throw ('Owned '+$Family+' echo server failed.')}
        Start-Sleep -Milliseconds 100
    }
    if(-not(Test-Path -LiteralPath $ready)){throw ('Owned '+$Family+' echo server not ready.')}
    [int](Get-Content -LiteralPath $ready -Raw|ConvertFrom-Json).port
}
try{
    Assert-LabMutationAuthorized
    $criticalAdapters=@(Get-CriticalAdapterBaseline)
    $productionBefore=Get-ProductionState $criticalAdapters
    Write-LabJson (Join-Path $RunDirectory 'production-before.json') $productionBefore
    if(@(Get-NetIPAddress|Where-Object {$_.IPAddress -in @($ip4,$ip6)}).Count){throw 'Reserved test addresses already in use.'}
    if(Get-VMSwitch|Where-Object {$_.Name -eq $name}){throw 'Lab switch already exists.'}
    Write-LabJson (Join-Path $RunDirectory 'proposal.json') @{runId=$runId;scope='New internal switch management adapter only';switchName=$name;ipv4=$ip4;ipv6=$ip6;uplink=$false;NAT=$false;defaultGateway=$false;productionWrites=$false;limitations='Same-host socket tests; not virtual-switch forwarding or VM isolation'}
    if(-not $PSCmdlet.ShouldProcess($name,'Create disposable internal network; add/remove/restore only owned test addresses')){$preview=$true;return}
    # Establish watchdog coverage before the first host write. If creation dies
    # before its exact GUID is durable, the watchdog records manual recovery.
    Write-LabJson (Join-Path $RunDirectory 'creation-intent.json') @{runId=$runId;switchName=$name;phase='ABOUT_TO_CREATE';time=[DateTimeOffset]::UtcNow.ToString('o')}
    $parent=Get-Process -Id $PID
    $watch=Start-HiddenLabProcess -File (Join-Path $PSScriptRoot 'Watch-Lab.ps1') -Arguments @('-RunDirectory',$RunDirectory,'-ParentProcessId',"$PID",'-ParentStartTicks',"$($parent.StartTime.ToUniversalTime().Ticks)",'-AllowMutation','-LabConfirmation',$LabConfirmation)
    for($i=0;$i -lt 50 -and -not(Test-Path -LiteralPath (Join-Path $RunDirectory 'watch-ready.json'));$i++){
        if($watch.HasExited){throw 'Watchdog exited before resource creation.'}
        Start-Sleep -Milliseconds 100
    }
    if(-not(Test-Path -LiteralPath (Join-Path $RunDirectory 'watch-ready.json'))){throw 'Watchdog readiness was not confirmed; no switch created.'}
    $created=New-VMSwitch -Name $name -SwitchType Internal -ErrorAction Stop
    Write-LabJson (Join-Path $RunDirectory 'created-switch.json') @{runId=$runId;switchName=$name;switchId=$created.Id.ToString()}

    for($i=0;$i -lt 40;$i++){
        $managed=@(Get-VMNetworkAdapter -ManagementOS|Where-Object {$_.SwitchId -eq $created.Id})
        $adapter=@(Get-NetAdapter -IncludeHidden|Where-Object {$managed.Count -eq 1 -and $_.MacAddress -and $_.MacAddress.Replace('-','') -eq $managed[0].MacAddress})
        if($adapter.Count -eq 1){break};Start-Sleep -Milliseconds 200
    }
    if($adapter.Count -ne 1){throw 'Cannot identify new management adapter.'}
    $control=New-LabControl -RunId $runId -SwitchId $created.Id -AdapterGuid $adapter[0].InterfaceGuid
    Write-LabJson (Join-Path $RunDirectory 'control.json') $control
    $x=Get-LabIdentity $RunDirectory;$index=$x.adapter.ifIndex
    Set-DnsClient -InterfaceIndex $index -RegisterThisConnectionsAddress $false -UseSuffixWhenRegistering $false -ErrorAction Stop
    foreach($family in @('IPv4','IPv6')){
        $x=Get-LabIdentity $RunDirectory
        Set-NetIPInterface -InterfaceIndex $x.adapter.ifIndex -AddressFamily $family -Dhcp Disabled -AutomaticMetric Disabled -InterfaceMetric 9000 -ErrorAction Stop
    }
    $x=Get-LabIdentity $RunDirectory
    Set-NetIPInterface -InterfaceIndex $x.adapter.ifIndex -AddressFamily IPv6 -RouterDiscovery Disabled -ErrorAction Stop
    foreach($address in @($ip4,$ip6)){
        $x=Get-LabIdentity $RunDirectory
        New-NetIPAddress -InterfaceIndex $x.adapter.ifIndex -IPAddress $address -PrefixLength $(if($address -eq $ip4){32}else{128}) -SkipAsSource $true -PolicyStore ActiveStore -ErrorAction Stop|Out-Null
        Wait-LabAddress $x.adapter.ifIndex $address
    }
    Assert-ProductionStable 'setup'
    $snapshot=New-LabAddressSnapshot -Control $control -Addresses @(Get-LabConfig $RunDirectory)
    $snapshotPath=Join-Path $RunDirectory 'lab-address-snapshot.json';Write-LabJson $snapshotPath $snapshot
    $snapshotJson=Get-Content -LiteralPath $snapshotPath -Raw -Encoding UTF8
    $snapshotSchema=Join-Path $skillRoot 'schemas/LabAddressSnapshot.schema.json'
    if(-not(Test-Json -Json $snapshotJson -SchemaFile $snapshotSchema -ErrorAction SilentlyContinue)){throw 'Created lab snapshot failed schema validation.'}
    $trustedHash=(Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash
    Write-LabJson (Join-Path $RunDirectory 'lab-address-snapshot.manifest.json') @{sha256=$trustedHash;kind='Lab-only conditional address restore; not installed skill observation snapshot'}
    $port4=Start-LabEchoServer 'ipv4' $ip4
    $port6=Start-LabEchoServer 'ipv6' $ip6
    Test-LabEcho 'ipv4-before' $ip4 $port4 $true;Test-LabEcho 'ipv6-before' $ip6 $port6 $true
    foreach($item in @(@{family='ipv4';address=$ip4;port=$port4},@{family='ipv6';address=$ip6;port=$port6})){
        Stop-LabEchoServer $item.family
        Remove-LabAddress $RunDirectory $item.address
        Test-LabEcho ($item.family+'-fault') $item.address $item.port $false
        Write-LabJson (Join-Path $RunDirectory ($item.family+'-fault-config.json')) @{addresses=@(Get-LabConfig $RunDirectory)}
        Restore-LabSnapshot $RunDirectory $snapshotPath $trustedHash
        $item.port=Start-LabEchoServer $item.family $item.address
        Test-LabEcho ($item.family+'-restored') $item.address $item.port $true
        Assert-ProductionStable ($item.family+'-restored')
    }
    $corrupt=Join-Path $RunDirectory 'lab-address-snapshot-corrupt.json';[IO.File]::WriteAllText($corrupt,([IO.File]::ReadAllText($snapshotPath)+' '))
    $beforeCount=$script:LabMutationCount;$beforeConfig=Get-LabConfig $RunDirectory;$rejected=$false
    try{Restore-LabSnapshot $RunDirectory $corrupt $trustedHash}catch{$rejected=$_.Exception.Message -like 'Lab snapshot hash mismatch*'}
    $afterConfig=Get-LabConfig $RunDirectory
    $zeroMutation=($beforeCount -eq $script:LabMutationCount -and ($beforeConfig|ConvertTo-Json -Depth 4 -Compress) -ceq ($afterConfig|ConvertTo-Json -Depth 4 -Compress))
    $tests.Add(@{id='corrupt-snapshot';status=$(if($rejected -and $zeroMutation){'PASS'}else{'FAIL'});rejected=$rejected;zeroMutation=$zeroMutation})
    if(-not($rejected -and $zeroMutation)){throw 'Corrupt snapshot gate failed.'}
    Stop-LabEchoServer 'ipv4'
    $worker=Start-HiddenLabProcess -File (Join-Path $PSScriptRoot 'Interrupt-Lab.ps1') -Arguments @('-RunDirectory',$RunDirectory,'-AllowMutation','-LabConfirmation',$LabConfirmation) -Wait
    $journal=Get-Content -LiteralPath (Join-Path $RunDirectory 'interrupted-journal.json') -Raw|ConvertFrom-Json
    if($worker.ExitCode -ne 77 -or $journal.state -ne 'APPLYING'){throw 'Interruption scenario not observed.'}
    Test-LabEcho 'interrupted-worker-fault' $ip4 $port4 $false
    $actual=Get-LabConfig $RunDirectory
    if(@($actual|Where-Object {$_.IPAddress -eq $ip4}).Count){throw 'Interruption did not remove expected address.'}
    Restore-LabSnapshot $RunDirectory $snapshotPath $trustedHash
    $port4=Start-LabEchoServer 'ipv4' $ip4
    Test-LabEcho 'interrupted-worker-restored' $ip4 $port4 $true
    Write-LabJson (Join-Path $RunDirectory 'interruption-recovery.json') @{childExit=77;observedJournalState=$journal.state;decision='Read current state; restore missing exact owned address from validated snapshot, no blind apply replay';finalState='ROLLED_BACK';limits='Supervisor survived; not host reboot or parent/watchdog crash validation'}
    Assert-ProductionStable 'tests-complete'
    $restored=@(Get-LabConfig $RunDirectory)
    if(($restored|ConvertTo-Json -Depth 4 -Compress) -cne ($snapshot.addresses|ConvertTo-Json -Depth 4 -Compress)){throw 'Restored lab configuration differs from snapshot.'}
}catch{$failed=$_.Exception.Message;Write-LabJson (Join-Path $RunDirectory 'failure.json') @{error=$failed;time=[DateTimeOffset]::Now.ToString('o')}}
finally{
    foreach($job in @($servers.Values)){Stop-Job -Job $job -ErrorAction SilentlyContinue;Remove-Job -Job $job -Force -ErrorAction SilentlyContinue}
    $cleanup=Invoke-LabCleanup -RunDirectory $RunDirectory -Created $created -Control $control
    if($cleanup.failure){$failed=$cleanup.failure}
    if($productionBefore){try{Assert-ProductionStable 'after-cleanup'}catch{if(-not $cleanup.failure){$failed=$_.Exception.Message}}}
    $cleanupVerified=[bool]$cleanup.cleanupVerified
    $terminalStatus=Get-LabTerminalStatus -Failure $failed -Preview $preview
    Write-LabTerminalRecords -RunDirectory $RunDirectory -Status $terminalStatus -Failure $failed -CleanupVerified $cleanupVerified -Tests @($tests.ToArray())
    if($watch){$null=$watch.WaitForExit(4000)}
    Get-Content -LiteralPath (Join-Path $RunDirectory 'result.json') -Raw

}
if($failed){exit 1}
