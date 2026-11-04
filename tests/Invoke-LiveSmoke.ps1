#Requires -Version 7.4
[CmdletBinding()]
param([string]$OutputDirectory=(Join-Path ([IO.Path]::GetTempPath()) "network-live-smoke-$([guid]::NewGuid())"))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
$entry=Join-Path $root 'scripts/entrypoints/Invoke-NetworkSkill.ps1'
[IO.Directory]::CreateDirectory($OutputDirectory)|Out-Null
$results=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[scriptblock]$Body){
    try{& $Body|Out-Null;$results.Add(@{name=$Name;status='PASS';reason=$null})}
    catch{$results.Add(@{name=$Name;status='FAIL';reason=$_.Exception.Message})}
}
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Start-Endpoint([string]$Address,[bool]$Tls){
    $ready=Join-Path $OutputDirectory ("ready-$([guid]::NewGuid()).json")
    $job=Start-Job -ArgumentList $Address,$Tls,$ready -ScriptBlock {
        param($Address,$Tls,$Ready)
        $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($Address),0)
        $certificate=$null;$key=$null
        try{
            if($Address -eq '::1'){$listener.Server.DualMode=$false}
            $listener.Start()
            [IO.File]::WriteAllText($Ready,(@{port=$listener.LocalEndpoint.Port}|ConvertTo-Json))
            $client=$listener.AcceptTcpClient()
            try{
                $client.ReceiveTimeout=3000;$client.SendTimeout=3000
                $stream=$client.GetStream()
                if($Tls){
                    $key=[Security.Cryptography.RSA]::Create(2048)
                    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(
                        'CN=untrusted.network.test',$key,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
                    $certificate=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddMinutes(5))
                    $ssl=[Net.Security.SslStream]::new($stream,$false)
                    try{$ssl.AuthenticateAsServer($certificate)}catch{}finally{$ssl.Dispose()}
                }else{
                    $buffer=[byte[]]::new(1)
                    $null=$stream.Read($buffer,0,1)
                }
            }finally{$client.Dispose()}
        }finally{
            $listener.Stop()
            if($certificate){$certificate.Dispose()}
            if($key){$key.Dispose()}
        }
    }
    for($index=0;$index -lt 100 -and -not(Test-Path -LiteralPath $ready);$index++){
        if($job.State -eq 'Failed'){throw 'Local endpoint failed to start.'}
        Start-Sleep -Milliseconds 50
    }
    if(-not(Test-Path -LiteralPath $ready)){Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue;throw 'Local endpoint readiness timed out.'}
    @{job=$job;port=[int](Get-Content -LiteralPath $ready -Raw|ConvertFrom-Json).port}
}
foreach($address in @('127.0.0.1','::1')){
    Check "Real path-probe TCP on $address" {
        $endpoint=Start-Endpoint $address $false
        try{
            $result=& $entry -Intent path-probe -ProbeAddress $address -ProbePort $endpoint.port -TimeoutSeconds 3
            Assert ($result.status -eq 'PASS' -and $result.tcp -eq 'PASS' -and $result.tls -eq 'NOT_RUN' -and $result.socketClosed) 'Loopback TCP probe failed.'
            Assert ($result.pathProof -like 'UNKNOWN*') 'Loopback was mislabeled as native egress proof.'
        }finally{Stop-Job $endpoint.job -ErrorAction SilentlyContinue;Remove-Job $endpoint.job -Force -ErrorAction SilentlyContinue}
    }
}
Check 'TLS rejects an untrusted local certificate without bypass' {
    $endpoint=Start-Endpoint '127.0.0.1' $true
    try{
        $result=& $entry -Intent path-probe -ProbeAddress '127.0.0.1' -ProbePort $endpoint.port -TlsName 'untrusted.network.test' -TimeoutSeconds 5
        Assert ($result.status -eq 'FAIL' -and $result.tcp -eq 'PASS' -and $result.tls -eq 'FAIL' -and $result.failedStage -eq 'tls' -and $result.socketClosed) 'TLS certificate validation was bypassed or failed in the wrong stage.'
    }finally{Stop-Job $endpoint.job -ErrorAction SilentlyContinue;Remove-Job $endpoint.job -Force -ErrorAction SilentlyContinue}
}
Check 'Native event watcher registers and disposes without network writes' {
    $result=& $entry -Intent watch-events -StateRoot (Join-Path $OutputDirectory 'events') -DurationSeconds 1
    Assert ($result.status -eq 'PASS' -and -not $result.networkChanges -and $result.dropped -eq 0) 'Native watcher could not register all sources.'
}
Check 'Installer backs up previous version and byte-verifies the package' {
    $destination=Join-Path $OutputDirectory 'installed\windows-network-fixer'
    $backupRoot=Join-Path $OutputDirectory 'backups'
    [IO.Directory]::CreateDirectory($destination)|Out-Null
    [IO.File]::WriteAllText((Join-Path $destination 'SKILL.md'),'old-skill-sentinel')
    $result=& (Join-Path $root 'scripts/install/Install-NetworkSkill.ps1') -Destination $destination -BackupRoot $backupRoot
    Assert ($result.status -eq 'PASS' -and $result.files -ge 30) 'Installer failed.'
    Assert ([IO.File]::ReadAllText((Join-Path $result.backup 'SKILL.md')) -ceq 'old-skill-sentinel') 'Backup did not retain old bytes.'
    $run=& (Join-Path $destination 'scripts/entrypoints/Invoke-NetworkSkill.ps1') -Fixture -StateRoot (Join-Path $OutputDirectory 'installed-observation')
    Assert ($run.status -eq 'PASS' -and $run.synthetic) 'Installed package cannot run fixture.'
}
$summary=@{
    passed=@($results|Where-Object status -EQ PASS).Count;failed=@($results|Where-Object status -EQ FAIL).Count
    kind='Live loopback TCP/TLS, native read-only subscriptions, and package install into isolated files. No production network settings changed.'
    tests=@($results)
}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'live-smoke-results.json'),(ConvertTo-Json -InputObject $summary -Depth 10))
$summary|ConvertTo-Json -Depth 10
if($summary.failed){exit 1}
