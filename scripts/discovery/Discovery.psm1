#Requires -Version 7.4
Set-StrictMode -Version Latest

function Get-NetworkDiscovery {
    param([Parameter(Mandatory)][hashtable]$Context, [switch]$ProbeDns, [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}$')][string]$DnsName='example.com')
    $ErrorActionPreference='Stop'
    $collectors=[ordered]@{
        environment={
            if(-not $IsWindows){throw 'Windows required'}
            $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            [pscustomobject]@{windowsVersion=$os.Version;build=$os.BuildNumber;architecture=$os.OSArchitecture;powershell=$PSVersionTable.PSVersion.ToString();compartmentScope='default unless explicitly specified';sampling='sequential, not atomic'}
        }
        interfaces={
            Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object InterfaceGuid,ifIndex,Name,InterfaceDescription,@{n='Status';e={$_.Status.ToString()}},Virtual,HardwareInterface
        }
        addresses={
            Get-NetIPAddress -ErrorAction Stop | Select-Object InterfaceIndex,InterfaceAlias,@{n='AddressFamily';e={$_.AddressFamily.ToString()}},IPAddress,PrefixLength,@{n='AddressState';e={$_.AddressState.ToString()}},@{n='PrefixOrigin';e={$_.PrefixOrigin.ToString()}},@{n='SuffixOrigin';e={$_.SuffixOrigin.ToString()}}
        }
        ipInterfaces={
            Get-NetIPInterface -ErrorAction Stop | Select-Object InterfaceIndex,InterfaceAlias,@{n='AddressFamily';e={$_.AddressFamily.ToString()}},@{n='ConnectionState';e={$_.ConnectionState.ToString()}},@{n='Dhcp';e={$_.Dhcp.ToString()}},@{n='RouterDiscovery';e={$_.RouterDiscovery.ToString()}},InterfaceMetric
        }
        routes={
            foreach($store in @('ActiveStore','PersistentStore')) {
                Get-NetRoute -PolicyStore $store -ErrorAction Stop | Select-Object InterfaceIndex,@{n='AddressFamily';e={$_.AddressFamily.ToString()}},DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,CompartmentId,@{n='Store';e={$store}}
            }
        }
        dns={ Get-DnsClientServerAddress -ErrorAction Stop | Select-Object InterfaceIndex,InterfaceAlias,@{n='AddressFamily';e={$_.AddressFamily.ToString()}},ServerAddresses }
        nrpt={ Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Select-Object Namespace,NameServers,DnsSecValidationRequired }
        proxies={
            $p=Get-ItemProperty -ErrorAction Stop -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            # ProxyServer and PAC URLs can contain credentials. Retain presence only.
            $enabled=$p.PSObject.Properties['ProxyEnable']; $server=$p.PSObject.Properties['ProxyServer']; $pac=$p.PSObject.Properties['AutoConfigURL']
            [pscustomobject]@{scope='collector HKCU only';ProxyEnable=if($enabled){$enabled.Value}else{$null};ProxyServerPresent=($null -ne $server -and [bool]$server.Value);AutoConfigUrlPresent=($null -ne $pac -and [bool]$pac.Value);AutoDetect='UNKNOWN';WinHttp='UNKNOWN; use separate whitelist collector'}
        }
        processes={
            Get-Process -ErrorAction Stop | Where-Object {$_.ProcessName -in @('FlClash','FlClashCore','FlClashHelperService')} | ForEach-Object {
                $path=$_.Path
                [pscustomobject]@{name=$_.ProcessName;processId=$_.Id;path=$path;fileVersion=if($path){(Get-Item -LiteralPath $path).VersionInfo.FileVersion}else{$null}}
            }
        }
        listeners={
            $owners=@(Get-Process -ErrorAction Stop | Where-Object {$_.ProcessName -eq 'FlClashCore'} | Select-Object -ExpandProperty Id)
            Get-NetTCPConnection -ErrorAction Stop -State Listen | Where-Object {$_.OwningProcess -in $owners} | Select-Object LocalAddress,LocalPort,OwningProcess
        }
        dataDirectories={
            # Existence-only candidates; they are never declared to be the active process directory.
            foreach($base in @($env:APPDATA,$env:LOCALAPPDATA)) {
                $candidate=Join-Path $base 'com.follow/clash'
                if(Test-Path -LiteralPath $candidate -PathType Container) {
                    $dir=Get-Item -LiteralPath $candidate
                    if($dir.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
                    [pscustomobject]@{candidatePath=$dir.FullName;verifiedActive=$false;configYamlPresent=(Test-Path -LiteralPath (Join-Path $candidate 'config.yaml') -PathType Leaf);databasePresent=(Test-Path -LiteralPath (Join-Path $candidate 'database.sqlite') -PathType Leaf)}
                }
            }
        }
    }
    $bundles=[ordered]@{}
    foreach($name in $collectors.Keys){$bundles[$name]=Invoke-NetworkRead -Name $name -Context $Context -Read $collectors[$name]}
    if($ProbeDns){
        foreach($type in @('A','AAAA')) {
            $bundles["dnsProbe$type"]=Invoke-NetworkRead -Name "system DNS $type $DnsName; TUN path unproven" -Context $Context -Read {
                Resolve-DnsName -Name $DnsName -Type $type -DnsOnly -QuickTimeout | Select-Object Name,@{n='Type';e={$_.Type.ToString()}},IPAddress
            }
        }
    }
    $bundles
}

function Test-NetworkCoreExecutablePath {
    param(
        [Parameter(Mandatory)][string]$ProcessPath,
        [string]$VerifiedExecutablePath
    )
    Test-NetworkSafePathSyntax $ProcessPath | Out-Null
    $processFull = [IO.Path]::GetFullPath($ProcessPath)
    $leaf = [IO.Path]::GetFileName($processFull)
    if ($leaf -notin @('FlClashCore.exe','flclashcore.exe')) {
        throw 'Controller owner executable name is not FlClashCore.exe.'
    }
    if ($VerifiedExecutablePath) {
        Test-NetworkSafePathSyntax $VerifiedExecutablePath | Out-Null
        $verifiedFull = [IO.Path]::GetFullPath($VerifiedExecutablePath)
        if (-not $processFull.Equals($verifiedFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Controller owner executable does not match the user-verified path.'
        }
        return $true
    }
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $root = [IO.Path]::GetFullPath((Join-Path $programFiles 'FlClash')).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $separator = [IO.Path]::DirectorySeparatorChar
    if (-not $processFull.StartsWith($root + $separator, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Controller owner executable is outside the default verified FlClash install root.'
    }
    $true
}


# The callback can run on a .NET thread without a PowerShell runspace. It returns
# only the already connected and owner-verified stream; it never reconnects.
if (-not ('FlClashNetwork.VerifiedConnection' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
namespace FlClashNetwork {
    public static class VerifiedConnection {
        public static SocketsHttpHandler CreateHandler(Stream stream) {
            int consumed = 0;
            var handler = new SocketsHttpHandler {
                UseProxy = false, AllowAutoRedirect = false,
                MaxConnectionsPerServer = 1,
                PooledConnectionLifetime = TimeSpan.Zero
            };
            handler.ConnectCallback = (context, token) => {
                token.ThrowIfCancellationRequested();
                if (Interlocked.Exchange(ref consumed, 1) != 0)
                    throw new IOException("Verified connection cannot be replaced or reused.");
                return new ValueTask<Stream>(stream);
            };
            return handler;
        }
    }
}
'@
}

function Test-NetworkControllerConnection {
    param(
        [Parameter(Mandatory)][int]$ExpectedProcessId,
        [Parameter(Mandatory)][long]$ExpectedStartTicks,
        [Parameter(Mandatory)][int]$CurrentProcessId,
        [Parameter(Mandatory)][long]$CurrentStartTicks,
        [Parameter(Mandatory)][bool]$ProcessAlive,
        [Parameter(Mandatory)][Net.IPEndPoint]$ClientEndpoint,
        [Parameter(Mandatory)][Net.IPEndPoint]$ServerEndpoint,
        [Parameter(Mandatory)][object[]]$ServerConnections
    )
    if (-not $ProcessAlive -or $ExpectedProcessId -ne $CurrentProcessId -or $ExpectedStartTicks -ne $CurrentStartTicks) {
        throw 'Verified controller process identity changed or exited.'
    }
    $owned = @($ServerConnections | Where-Object {
        [int]$_.OwningProcess -eq $ExpectedProcessId -and
        [string]$_.State -eq 'Established' -and
        [Net.IPAddress]::Parse([string]$_.LocalAddress).Equals($ServerEndpoint.Address) -and
        [int]$_.LocalPort -eq $ServerEndpoint.Port -and
        [Net.IPAddress]::Parse([string]$_.RemoteAddress).Equals($ClientEndpoint.Address) -and
        [int]$_.RemotePort -eq $ClientEndpoint.Port
    })
    if ($owned.Count -ne 1) { throw 'Connected controller socket has no exact verified server owner.' }
    $true
}

function Get-NetworkController {
    param(
        [Parameter(Mandatory)][uri]$ControllerUri,
        [Parameter(Mandatory)][hashtable]$Context,
        [Security.SecureString]$ApiSecret,
        [ValidateRange(1,15)][int]$TimeoutSeconds=5,
        [string]$CoreExecutablePath
    )
    $ErrorActionPreference='Stop'
    # Address must be literal loopback. DNS names, alternate paths, userinfo and redirects are forbidden.
    $address=$null
    if($ControllerUri.Scheme -ne 'http' -or -not [Net.IPAddress]::TryParse($ControllerUri.Host.Trim('[',']'),[ref]$address) -or -not [Net.IPAddress]::IsLoopback($address) -or $ControllerUri.UserInfo -or $ControllerUri.AbsolutePath -ne '/' -or $ControllerUri.Query -or $ControllerUri.Fragment){throw 'Controller must be a literal loopback http root URI without credentials, query or fragment.'}
    $bundles=[ordered]@{}
    foreach($endpoint in @('version','configs')) {
        $bundles[$endpoint]=Invoke-NetworkRead -Name "verified FlClashCore controller GET /$endpoint" -Context $Context -Read {
            $owners=@(Get-Process -ErrorAction Stop | Where-Object {
                $_.ProcessName -eq 'FlClashCore' -and
                (Test-NetworkCoreExecutablePath -ProcessPath $_.Path -VerifiedExecutablePath $CoreExecutablePath)
            })
            $allowed=@($address.ToString(), $(if($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){'0.0.0.0'}else{'::'}))
            $listening=@(Get-NetTCPConnection -ErrorAction Stop -State Listen -LocalPort $ControllerUri.Port | Where-Object {$_.OwningProcess -in @($owners | ForEach-Object Id) -and $_.LocalAddress -in $allowed})
            if($listening.Count -ne 1){throw 'No unique current PID-owned controller listener.'}
            $owner=@($owners | Where-Object Id -eq $listening[0].OwningProcess)[0]
            $socket=$null;$stream=$null;$handler=$null;$client=$null;$connectCancel=$null
            try {
                # Retain the OS process handle until response disposal. The authenticated
                # HTTP request can only use this connected socket, never a replacement listener.
                $null=$owner.Handle
                $ownerTicks=$owner.StartTime.ToUniversalTime().Ticks
                $socket=[Net.Sockets.Socket]::new($address.AddressFamily,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
                $connectCancel=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
                $null=$socket.ConnectAsync([Net.IPEndPoint]::new($address,$ControllerUri.Port),$connectCancel.Token).AsTask().GetAwaiter().GetResult()
                $connections=@(Get-NetTCPConnection -ErrorAction Stop -State Established -LocalPort $ControllerUri.Port)
                $owner.Refresh()
                $alive=-not $owner.HasExited
                if (-not $alive) { throw 'Verified controller exited before authentication.' }
                Test-NetworkCoreExecutablePath -ProcessPath $owner.Path -VerifiedExecutablePath $CoreExecutablePath | Out-Null
                Test-NetworkControllerConnection -ExpectedProcessId $owner.Id -ExpectedStartTicks $ownerTicks -CurrentProcessId $owner.Id -CurrentStartTicks $owner.StartTime.ToUniversalTime().Ticks -ProcessAlive $alive -ClientEndpoint $socket.LocalEndPoint -ServerEndpoint $socket.RemoteEndPoint -ServerConnections $connections | Out-Null
                $stream=[Net.Sockets.NetworkStream]::new($socket,$true)
                $handler=[FlClashNetwork.VerifiedConnection]::CreateHandler($stream)
                $client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds($TimeoutSeconds)
                if($ApiSecret){
                    $plain=[Net.NetworkCredential]::new('', $ApiSecret).Password
                    $client.DefaultRequestHeaders.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$plain)
                    $plain=$null
                }
                $response=$client.GetAsync([uri]::new($ControllerUri,$endpoint),[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                try {
                    $code=[int]$response.StatusCode
                    if($code -ne 200){throw "HTTP $code"}
                    if($response.Content.Headers.ContentLength -gt 1048576){throw 'Response too large'}
                    $stream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                    try {
                        $buffer=[byte[]]::new(1048577);$total=0
                        $cancel=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
                        try {while($total -lt $buffer.Length){$count=$stream.ReadAsync($buffer,$total,$buffer.Length-$total,$cancel.Token).GetAwaiter().GetResult();if($count -eq 0){break};$total+=$count}}finally{$cancel.Dispose()}
                        if($total -gt 1048576){throw 'Response too large'}
                        $data=[Text.Encoding]::UTF8.GetString($buffer,0,$total)|ConvertFrom-Json -AsHashtable
                        if($endpoint -eq 'version'){@{meta=$data['meta'];version=$data['version']}}else{
                            $safe=@{};foreach($key in @('port','socks-port','mixed-port','mode','allow-lan','ipv6')){if($data.ContainsKey($key)){$safe[$key]=$data[$key]}}
                            if($data['tun'] -is [hashtable]){$safe.tun=@{};foreach($key in @('enable','device','stack','auto-route','strict-route')){if($data.tun.ContainsKey($key)){$safe.tun[$key]=$data.tun[$key]}}}
                            $safe
                        }
                    } finally {$stream.Dispose()}
                } finally {$response.Dispose()}
            } finally {
                if($client){$client.Dispose()};if($handler){$handler.Dispose()}
                if($stream){$stream.Dispose()};if($socket){$socket.Dispose()}
                if($connectCancel){$connectCancel.Dispose()};$owner.Dispose()
            }
        }
        # Preserve HTTP status classification without exposing exception messages or response bodies.
        if($bundles[$endpoint].record.collectionStatus -eq 'BLOCKED'){$bundles[$endpoint].record.error.message='Controller read blocked: verify local ownership, authentication and response validity. No retry or configuration change performed.'}
    }
    $bundles
}
Export-ModuleMember -Function Get-NetworkDiscovery,Get-NetworkController,Test-NetworkCoreExecutablePath,Test-NetworkControllerConnection
