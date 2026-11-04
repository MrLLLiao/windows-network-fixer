#Requires -Version 7.4
Set-StrictMode -Version Latest

function Invoke-NetworkPathProbe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Address, [ValidateRange(1,65535)][int]$Port=443,
        [string]$SourceAddress, [string]$TlsName, [ValidateRange(1,30)][int]$TimeoutSeconds=5)
    $remote = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$remote)) { throw 'Path probe requires an explicit numeric destination.' }
    $local = $null
    if ($SourceAddress -and (-not [Net.IPAddress]::TryParse($SourceAddress,[ref]$local) -or
        $remote.AddressFamily -ne $local.AddressFamily)) { throw 'Source address family mismatch.' }
    if ($TlsName -and ($TlsName.Length -gt 253 -or $TlsName -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$')) {
        throw 'Invalid TLS hostname.'
    }
    $result = [ordered]@{
        status='FAIL'; family=if ($remote.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {'IPv4'} else {'IPv6'}
        destination=$remote.ToString(); port=$Port; source=$SourceAddress; tlsName=$TlsName
        startedAt=[DateTimeOffset]::UtcNow.ToString('o'); route=@(); tcp='NOT_RUN'; tls='NOT_RUN'
        failedStage=$null; nativeError=$null; pathProof='UNKNOWN; TUN, WFP or another interception may apply'
        connectionMilliseconds=$null; localEndpoint=$null; socketClosed=$false; routeStatus='NOT_RUN'
    }
    $socket = $null
    $stream = $null
    $tls = $null
    $cancel = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
    try {
        try {
            $result.route = @(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop | Select-Object InterfaceIndex,IPAddress,DestinationPrefix,NextHop,RouteMetric)
            $result.routeStatus = 'PASS'
        } catch { $result.routeStatus = 'BLOCKED' }
        $result.failedStage = 'bind'
        $socket = [Net.Sockets.Socket]::new($remote.AddressFamily,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
        if ($null -ne $local) { $socket.Bind([Net.IPEndPoint]::new($local,0)) }
        $result.failedStage = 'connect'
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $null = $socket.ConnectAsync([Net.IPEndPoint]::new($remote,$Port),$cancel.Token).AsTask().GetAwaiter().GetResult()
        $timer.Stop()
        $result.connectionMilliseconds = $timer.ElapsedMilliseconds
        $result.tcp = 'PASS'
        $result.localEndpoint = $socket.LocalEndPoint.ToString()
        if ($TlsName) {
            $result.failedStage = 'tls'
            $stream = [Net.Sockets.NetworkStream]::new($socket,$false)
            $tls = [Net.Security.SslStream]::new($stream,$false)
            $options = [Net.Security.SslClientAuthenticationOptions]::new()
            $options.TargetHost = $TlsName
            $options.CertificateRevocationCheckMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            $null = $tls.AuthenticateAsClientAsync($options,$cancel.Token).GetAwaiter().GetResult()
            $result.tls = 'PASS'
        }
        $result.status = 'PASS'
        $result.failedStage = $null
    } catch {
        if ($result.failedStage -eq 'connect') { $result.tcp = 'FAIL' }
        if ($result.failedStage -eq 'tls') { $result.tls = 'FAIL' }
        $exception = $_.Exception
        while ($null -ne $exception.InnerException) { $exception = $exception.InnerException }
        if ($exception -is [Net.Sockets.SocketException]) { $result.nativeError = $exception.NativeErrorCode }
    } finally {
        if ($tls) { $tls.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($socket) { $socket.Dispose(); $result.socketClosed = $true }
        $cancel.Dispose()
    }
    $result.endedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $result
}

Export-ModuleMember -Function Invoke-NetworkPathProbe
