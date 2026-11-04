#Requires -Version 7.4
Set-StrictMode -Version Latest

function Invoke-NetworkSocketProbe {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
        [ValidateRange(-1,2147483647)][int]$InterfaceIndex = -1,
        [Parameter(Mandatory)][ValidateLength(1,256)][string]$Nonce,
        [ValidateRange(250,30000)][int]$TimeoutMilliseconds = 3000
    )
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip)) {
        throw 'Socket probe requires a literal IPv4 or IPv6 address.'
    }
    if ($ip.AddressFamily -notin @(
        [Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.AddressFamily]::InterNetworkV6
    )) {
        throw 'Socket probe requires IPv4 or IPv6.'
    }
    $result = [ordered]@{
        schemaVersion = '1.0.0'
        path = 'same-host-socket'
        address = $ip.ToString()
        port = $Port
        addressFamily = if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
        interfaceIndex = if ($InterfaceIndex -ge 0) { $InterfaceIndex } else { $null }
        nonceSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::UTF8.GetBytes($Nonce)
            )
        ).ToLowerInvariant()
        nonceMatched = $false
        connectAttempted = $false
        bindSucceeded = $false
        failedStage = $null
        failureCode = $null
        errorType = $null
        socketError = $null
        nativeError = $null
        boundEndpoint = $null
        remoteEndpoint = $null
        startedAt = [DateTimeOffset]::Now.ToString('o')
        endedAt = $null
        listenerClosed = $null
        clientClosed = $false
        status = 'FAIL'
        proofScope = 'Verifies local source bind and same-host nonce echo only; it does not prove native or proxy egress.'
    }
    $socket = $null
    $stage = 'bind'
    try {
        $socket = [Net.Sockets.Socket]::new(
            $ip.AddressFamily,
            [Net.Sockets.SocketType]::Stream,
            [Net.Sockets.ProtocolType]::Tcp
        )
        if ($InterfaceIndex -ge 0) {
            $stage = 'socket-option'
            if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
                $socket.DualMode = $false
                $socket.SetSocketOption(
                    [Net.Sockets.SocketOptionLevel]::IPv6,
                    [Net.Sockets.SocketOptionName]31,
                    $InterfaceIndex
                )
            } else {
                $socket.SetSocketOption(
                    [Net.Sockets.SocketOptionLevel]::IP,
                    [Net.Sockets.SocketOptionName]31,
                    [Net.IPAddress]::HostToNetworkOrder($InterfaceIndex)
                )
            }
        }
        $stage = 'bind'
        $socket.Bind([Net.IPEndPoint]::new($ip, 0))
        $result.bindSucceeded = $true
        $result.boundEndpoint = $socket.LocalEndPoint.ToString()
        $stage = 'connect'
        $result.connectAttempted = $true
        $connectTask = $socket.ConnectAsync([Net.IPEndPoint]::new($ip, $Port))
        if (-not $connectTask.Wait($TimeoutMilliseconds)) {
            throw [TimeoutException]::new('Socket connect timeout.')
        }
        $null = $connectTask.GetAwaiter().GetResult()
        $result.remoteEndpoint = $socket.RemoteEndPoint.ToString()
        $socket.SendTimeout = $TimeoutMilliseconds
        $socket.ReceiveTimeout = $TimeoutMilliseconds
        $stage = 'send'
        $payload = [Text.Encoding]::UTF8.GetBytes($Nonce)
        $sent = 0
        while ($sent -lt $payload.Length) {
            $sent += $socket.Send($payload, $sent, $payload.Length - $sent, [Net.Sockets.SocketFlags]::None)
        }
        $stage = 'receive'
        $buffer = [byte[]]::new($payload.Length)
        $read = 0
        while ($read -lt $payload.Length) {
            $count = $socket.Receive(
                $buffer,
                $read,
                $payload.Length - $read,
                [Net.Sockets.SocketFlags]::None
            )
            if ($count -eq 0) {
                throw [IO.EndOfStreamException]::new('Socket echo ended before nonce length.')
            }
            $read += $count
        }
        $result.nonceMatched = [Text.Encoding]::UTF8.GetString($buffer) -ceq $Nonce
        if ($result.nonceMatched) {
            $result.status = 'PASS'
        } else {
            $stage = 'nonceVerify'
            $result.failureCode = 'NONCE_MISMATCH'
        }
    } catch {
        $base = $_.Exception.GetBaseException()
        $result.failedStage = $stage
        $result.failureCode = if ($stage -eq 'bind') {
            'SOURCE_BIND_FAILED'
        } elseif ($stage -eq 'connect') {
            'CONNECT_FAILED'
        } elseif ($stage -eq 'socket-option') {
            'SOURCE_INTERFACE_OPTION_FAILED'
        } else {
            'SOCKET_IO_FAILED'
        }
        $result.errorType = $base.GetType().Name
        if ($base -is [Net.Sockets.SocketException]) {
            $result.socketError = $base.SocketErrorCode.ToString()
            $result.nativeError = $base.NativeErrorCode
        }
    } finally {
        if ($socket) {
            $socket.Dispose()
        }
        $result.clientClosed = $true
    }
    $result.endedAt = [DateTimeOffset]::Now.ToString('o')
    $result
}

Export-ModuleMember -Function *-Network*
