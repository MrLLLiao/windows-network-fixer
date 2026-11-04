#Requires -Version 7.4
Set-StrictMode -Version Latest

function Get-NetworkRepairIdentity {
    if (-not $IsWindows) { throw 'Windows is required.' }
    @{
        machine = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
        principal = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    }
}

function Get-NetworkRepairDigest {
    param([AllowNull()][object]$Value)
    Get-NetworkHash (ConvertTo-NetworkCanonicalJson $Value)
}

function Copy-NetworkRepairValue {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Value)
    ConvertFrom-NetworkJson (ConvertTo-Json -InputObject $Value -Depth 50 -Compress)
}

function Read-NetworkRepairJson {
    param([Parameter(Mandatory)][string]$Path)
    $full = Assert-NetworkSafePath $Path
    $item = Get-Item -LiteralPath $full -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt 1048576) { throw 'Invalid repair JSON size or type.' }
    ConvertFrom-NetworkJson ([IO.File]::ReadAllText($full))
}

function Assert-NetworkRepairKeys {
    param([System.Collections.IDictionary]$Value, [string[]]$Required, [string[]]$Optional = @())
    if ($null -eq $Value) { throw 'A JSON object is required.' }
    foreach ($key in $Required) {
        if (-not $Value.Contains($key)) { throw "Missing repair field: $key" }
    }
    foreach ($key in $Value.Keys) {
        if ($key -cnotin @($Required + $Optional)) { throw "Unexpected repair field: $key" }
    }
}

function Assert-NetworkRepairRequest {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Request, [switch]$AllowMissingProgram)
    Assert-NetworkRepairKeys $Request @('kind','target','desired')
    $target = $Request.target
    $desired = $Request.desired
    switch -CaseSensitive ($Request.kind) {
        { $_ -in @('RouteMetric','RouteAdd','RouteRemove') } {
            Assert-NetworkRepairKeys $target @('interfaceGuid','family','destinationPrefix','nextHop')
            Assert-NetworkRepairKeys $desired $(if ($_ -eq 'RouteRemove') { @() } else { @('routeMetric') })
            $prefix = [string]$target.destinationPrefix
            $parts = $prefix.Split('/')
            $address = $null
            $nextHop = $null
            $prefixLength = 0
            if ($parts.Count -ne 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$address) -or
                -not [int]::TryParse($parts[1], [ref]$prefixLength) -or
                -not [Net.IPAddress]::TryParse([string]$target.nextHop, [ref]$nextHop)) {
                throw 'Route requires a numeric prefix and next hop.'
            }
            $maximum = if ($target.family -ceq 'IPv4') { 32 } else { 128 }
            if ($prefixLength -lt 0 -or $prefixLength -gt $maximum -or $address.AddressFamily -ne $nextHop.AddressFamily) {
                throw 'Invalid route prefix length or address family.'
            }
            $expectedFamily = if ($target.family -ceq 'IPv4') { 'InterNetwork' } else { 'InterNetworkV6' }
            if ($address.AddressFamily.ToString() -cne $expectedFamily) { throw 'Route family mismatch.' }
            $bytes = $address.GetAddressBytes()
            for ($bit = $prefixLength; $bit -lt $maximum; $bit++) {
                if ($bytes[[int][math]::Floor($bit / 8)] -band (1 -shl (7 - ($bit % 8)))) {
                    throw 'DestinationPrefix must use the canonical network address.'
                }
            }
            if ($Request.kind -ne 'RouteRemove' -and
                ($desired.routeMetric -isnot [long] -and $desired.routeMetric -isnot [int] -or
                $desired.routeMetric -lt 1 -or $desired.routeMetric -gt 65535)) { throw 'Invalid route metric.' }
        }
        'InterfaceMetric' {
            Assert-NetworkRepairKeys $target @('interfaceGuid','family')
            Assert-NetworkRepairKeys $desired @('automaticMetric','interfaceMetric')
            if ($desired.automaticMetric -cnotin @('Enabled','Disabled') -or
                ($desired.interfaceMetric -isnot [long] -and $desired.interfaceMetric -isnot [int]) -or
                $desired.interfaceMetric -lt 1 -or $desired.interfaceMetric -gt 9999) { throw 'Invalid interface metric.' }
        }
        'DnsServers' {
            Assert-NetworkRepairKeys $target @('interfaceGuid','family')
            Assert-NetworkRepairKeys $desired @('automatic','servers')
            if ($desired.automatic -isnot [bool] -or $desired.servers -isnot [array] -or
                $desired.servers.Count -gt 8 -or ($desired.automatic -and $desired.servers.Count) -or
                (-not $desired.automatic -and -not $desired.servers.Count)) { throw 'Invalid DNS mode or servers.' }
            foreach ($server in $desired.servers) {
                $parsed = $null
                if (-not [Net.IPAddress]::TryParse([string]$server, [ref]$parsed)) { throw 'DNS server must be numeric.' }
                $expectedFamily = if ($target.family -ceq 'IPv4') { 'InterNetwork' } else { 'InterNetworkV6' }
                if ($parsed.AddressFamily.ToString() -cne $expectedFamily) { throw 'DNS address family mismatch.' }
            }
        }
        'UserProxy' {
            Assert-NetworkRepairKeys $target @('scope')
            Assert-NetworkRepairKeys $desired @('enabled')
            if ($target.scope -cne 'CurrentUser' -or $desired.enabled -isnot [bool]) { throw 'Invalid proxy scope or mode.' }
        }
        'FirewallProfile' {
            Assert-NetworkRepairKeys $target @('profile')
            Assert-NetworkRepairKeys $desired @('enabled','logBlocked')
            if ($target.profile -cnotin @('Domain','Private','Public') -or
                $desired.enabled -cne $true -or $desired.logBlocked -cne $true) {
                throw 'FirewallProfile only enables protection and blocked-packet logging.'
            }
        }
        { $_ -in @('FirewallBlock','FirewallBlockAddress') } {
            $required = if ($Request.kind -eq 'FirewallBlockAddress') { @('direction','remoteAddress') } else { @('program','direction','remoteAddress') }
            Assert-NetworkRepairKeys $target $required
            Assert-NetworkRepairKeys $desired @('blocked')
            if ($desired.blocked -cne $true -or $target.direction -cnotin @('Inbound','Outbound')) { throw 'Only block rules are supported.' }
            $parsed = $null
            if (-not [Net.IPAddress]::TryParse([string]$target.remoteAddress, [ref]$parsed) -or
                [Net.IPAddress]::IsLoopback($parsed) -or $parsed.Equals([Net.IPAddress]::Any) -or
                $parsed.Equals([Net.IPAddress]::IPv6Any)) { throw 'A specific non-loopback remote IP is required.' }
            if ($Request.kind -eq 'FirewallBlock') {
                $program = Assert-NetworkSafePath ([string]$target.program)
                if (-not [IO.Path]::IsPathFullyQualified([string]$target.program) -or
                    (-not $AllowMissingProgram -and -not (Test-Path -LiteralPath $program -PathType Leaf))) { throw 'A verified absolute program path is required.' }
            }
        }
        default { throw 'Unsupported repair kind.' }
    }
    if ($target.Contains('interfaceGuid')) {
        $guid = [guid]::Empty
        if (-not [guid]::TryParse([string]$target.interfaceGuid, [ref]$guid) -or
            $guid -eq [guid]::Empty -or $target.family -cnotin @('IPv4','IPv6')) { throw 'Invalid adapter GUID or family.' }
    }
}

function Get-NetworkRepairAdapter {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        ([guid]$_.InterfaceGuid) -eq ([guid]$Target.interfaceGuid)
    })
    if ($adapters.Count -ne 1) { throw 'Adapter identity is absent or ambiguous.' }
    $adapters[0]
}

function Get-NetworkRepairRoutes {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target)
    $adapter = Get-NetworkRepairAdapter $Target
    @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily $Target.family -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.DestinationPrefix -ceq $Target.destinationPrefix -and $_.NextHop -ceq $Target.nextHop })
}

function Assert-NetworkRepairProxyPolicy {
    foreach ($path in @(
        'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings',
        'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings',
        'HKCU:\Software\Policies\Microsoft\Internet Explorer\Control Panel',
        'HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel'
    )) {
        if (Test-Path -LiteralPath $path) { throw 'Proxy policy exists; policy owner must handle this change.' }
    }
}

function Get-NetworkRepairState {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Request, [string]$RuleName)
    $target = $Request.target
    $adapter = if ($target.Contains('interfaceGuid')) { Get-NetworkRepairAdapter $target } else { $null }
    switch ($Request.kind) {
        { $_ -in @('RouteMetric','RouteAdd','RouteRemove') } {
            $routes = @(Get-NetworkRepairRoutes $target)
            if ($routes.Count -gt 1) { throw 'Route is ambiguous across compartments.' }
            $persistent = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily $target.family -PolicyStore PersistentStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -ceq $target.destinationPrefix -and $_.NextHop -ceq $target.nextHop })
            if ($persistent.Count) { throw 'Persistent route ownership requires a separate maintenance procedure.' }
            if (-not $routes.Count) { return @{ present = $false; routeMetric = $null } }
            if ([string]$routes[0].Protocol -ne 'NetMgmt' -or [string]$routes[0].Publish -ne 'No' -or
                $routes[0].ValidLifetime.TotalSeconds -lt 4294967294) {
                throw 'Only unpublished, infinite-lifetime, manually managed ActiveStore routes are repairable.'
            }
            @{ present = $true; routeMetric = [int]$routes[0].RouteMetric }
        }
        'InterfaceMetric' {
            $settings = @(Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily $target.family -PolicyStore ActiveStore -ErrorAction Stop)
            if ($settings.Count -ne 1) { throw 'IP interface is ambiguous.' }
            @{ automaticMetric = [string]$settings[0].AutomaticMetric; interfaceMetric = [int]$settings[0].InterfaceMetric }
        }
        'DnsServers' {
            $branch = if ($target.family -eq 'IPv4') { 'Tcpip' } else { 'Tcpip6' }
            $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$branch\Parameters\Interfaces\{$(([guid]$target.interfaceGuid).ToString('D'))}"
            $properties = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            $static = $properties.PSObject.Properties['NameServer']
            $servers = @()
            if ($static -and -not [string]::IsNullOrWhiteSpace([string]$static.Value)) {
                $servers = @(([string]$static.Value -split '[,;\s]+') | Where-Object { $_ })
            }
            foreach ($server in $servers) { $null = [Net.IPAddress]::Parse($server) }
            @{ automatic = ($servers.Count -eq 0); servers = @($servers) }
        }
        'UserProxy' {
            Assert-NetworkRepairProxyPolicy
            $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            $properties = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            $property = $properties.PSObject.Properties['ProxyEnable']
            $server = $properties.PSObject.Properties['ProxyServer']
            if ($Request.desired.enabled -and (-not $server -or -not $server.Value)) { throw 'No existing proxy endpoint to enable.' }
            if ($property -and ((Get-Item -LiteralPath $path).GetValueKind('ProxyEnable') -ne 'DWord' -or $property.Value -notin @(0,1))) { throw 'Unsupported proxy value type or value.' }
            $context = [ordered]@{}
            foreach ($name in @('ProxyServer','AutoConfigURL','AutoDetect')) {
                $value = $properties.PSObject.Properties[$name]
                $context[$name] = if ($value) { [string]$value.Value } else { $null }
            }
            @{
                present = ($null -ne $property)
                enabled = if ($property) { [bool]$property.Value } else { $false }
                endpointHash = Get-NetworkRepairDigest $context
            }
        }
        'FirewallProfile' {
            $profiles = @(Get-NetFirewallProfile -Name $target.profile -PolicyStore PersistentStore -ErrorAction Stop)
            if ($profiles.Count -ne 1) { throw 'Firewall profile is ambiguous.' }
            @{ enabled = [string]$profiles[0].Enabled; logBlocked = [string]$profiles[0].LogBlocked }
        }
        { $_ -in @('FirewallBlock','FirewallBlockAddress') } {
            if ($RuleName -notmatch '^CodexNetwork-[0-9a-f-]{36}$') { throw 'Invalid owned firewall rule name.' }
            $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -CEQ $RuleName)
            if ($rules.Count -gt 1) { throw 'Firewall rule identity is ambiguous.' }
            if (-not $rules.Count) { return @{ present = $false } }
            $rule = $rules[0]
            $application = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
            $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
            if ($application.Count -ne 1 -or $addresses.Count -ne 1) { throw 'Firewall filters are ambiguous.' }
            $ports = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
            $services = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
            $interfaces = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
            if ($ports.Count -ne 1 -or $services.Count -ne 1 -or $interfaces.Count -ne 1) { throw 'Firewall filter multiplicity changed.' }
            @{
                present = $true
                program = ([string]$application[0].Program).ToLowerInvariant()
                remoteAddress = @($addresses[0].RemoteAddress); direction = [string]$rule.Direction
                action = [string]$rule.Action; enabled = [string]$rule.Enabled
                profile = [string]$rule.Profile; description = [string]$rule.Description
                port = @(@{Protocol=[string]$ports[0].Protocol;LocalPort=@($ports[0].LocalPort);RemotePort=@($ports[0].RemotePort)})
                service = @(@{Service=[string]$services[0].Service})
                interface = @(@{InterfaceAlias=@($interfaces[0].InterfaceAlias)})
                guardHash = Get-NetworkRepairDigest @{
                    rule = ($rule | Select-Object Name,Description,Enabled,Profile,Direction,Action,EdgeTraversalPolicy,LooseSourceMapping,LocalOnlyMapping,Owner,PolicyAppId,RemoteDynamicKeywordAddresses)
                    application = @($application | Select-Object Program,Package)
                    address = @($addresses | Select-Object LocalAddress,RemoteAddress)
                    port = @($ports | Select-Object Protocol,LocalPort,RemotePort,IcmpType,DynamicTarget)
                    service = @($services | Select-Object Service)
                    interface = @($interfaces | Select-Object InterfaceAlias)
                    interfaceType = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop | Select-Object InterfaceType)
                    security = @($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop |
                        Select-Object Authentication,Encryption,OverrideBlockRules,LocalUser,RemoteUser,RemoteMachine)
                }
            }
        }
    }
}

function Get-NetworkRepairDesired {
    param([System.Collections.IDictionary]$Request, [System.Collections.IDictionary]$Before, [string]$RuleName)
    switch ($Request.kind) {
        'RouteMetric' {
            if (-not $Before.present) { throw 'RouteMetric requires an existing route.' }
            @{ present = $true; routeMetric = [int]$Request.desired.routeMetric }
        }
        'RouteAdd' {
            if ($Before.present) { throw 'RouteAdd requires an absent route.' }
            @{ present = $true; routeMetric = [int]$Request.desired.routeMetric }
        }
        'RouteRemove' {
            if (-not $Before.present) { throw 'RouteRemove requires an existing route.' }
            @{ present = $false; routeMetric = $null }
        }
        'InterfaceMetric' { @{ automaticMetric = $Request.desired.automaticMetric; interfaceMetric = [int]$Request.desired.interfaceMetric } }
        'DnsServers' { @{ automatic = $Request.desired.automatic; servers = @($Request.desired.servers) } }
        'UserProxy' { @{ present = $true; enabled = $Request.desired.enabled; endpointHash = $Before.endpointHash } }
        'FirewallProfile' { @{ enabled = 'True'; logBlocked = 'True' } }
        { $_ -in @('FirewallBlock','FirewallBlockAddress') } {
            if ($Before.present) { throw 'FirewallBlock requires an absent owned rule.' }
            @{
                present = $true
                program = if ($Request.kind -eq 'FirewallBlock') { $Request.target.program.ToLowerInvariant() } else { 'any' }
                remoteAddress = @($Request.target.remoteAddress)
                direction = $Request.target.direction; action = 'Block'; enabled = 'True'
                profile = 'Any'; description = "Owned by flclash-windows-network; $RuleName"
                port = @(@{Protocol='Any';LocalPort=@('Any');RemotePort=@('Any')})
                service = @(@{Service='Any'}); interface = @(@{InterfaceAlias=@('Any')})
                guardHash = $null
            }
        }
    }
}

function Set-NetworkRepairState {
    param([System.Collections.IDictionary]$Request, [System.Collections.IDictionary]$State, [string]$RuleName,
        [System.Collections.IDictionary]$ExpectedState)
    $ErrorActionPreference = 'Stop'
    if ($null -ne $ExpectedState) {
        $immediate = Get-NetworkRepairState $Request $RuleName
        if (-not (Test-NetworkRepairStateEqual $Request $immediate $ExpectedState)) {
            Stop-NetworkRepairForDrift 'Resource changed at the provider boundary.'
        }
    }
    $target = $Request.target
    $adapter = if ($target.Contains('interfaceGuid')) { Get-NetworkRepairAdapter $target } else { $null }
    switch ($Request.kind) {
        { $_ -in @('RouteMetric','RouteAdd','RouteRemove') } {
            $routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily $target.family -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -ceq $target.destinationPrefix -and $_.NextHop -ceq $target.nextHop })
            $decision = Get-NetworkRepairRouteDecision $Request $State $routes.Count
            if ($null -ne $ExpectedState -and $ExpectedState.present -and
                ($routes.Count -ne 1 -or [int]$routes[0].RouteMetric -ne [int]$ExpectedState.routeMetric -or
                [string]$routes[0].Protocol -ne 'NetMgmt')) { Stop-NetworkRepairForDrift 'Route value or ownership changed at the provider boundary.' }
            $freshAdapter = Get-NetworkRepairAdapter $target
            if ($freshAdapter.ifIndex -ne $adapter.ifIndex) { Stop-NetworkRepairForDrift 'Adapter binding changed before route mutation.' }
            switch ($decision) {
                'Create' {
                    New-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily $target.family -DestinationPrefix $target.destinationPrefix `
                        -NextHop $target.nextHop -RouteMetric $State.routeMetric -PolicyStore ActiveStore -Protocol NetMgmt `
                        -Publish No -Confirm:$false -ErrorAction Stop | Out-Null
                }
                'UpdateMetric' { $routes[0] | Set-NetRoute -RouteMetric $State.routeMetric -Confirm:$false -ErrorAction Stop }
                'Remove' { $routes[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
            }
            $afterAdapter = Get-NetworkRepairAdapter $target
            if ($afterAdapter.ifIndex -ne $adapter.ifIndex) {
                $bindingError = [InvalidOperationException]::new('Adapter binding changed during route mutation.')
                $bindingError.Data['ManualRecoveryRequired'] = $true
                throw $bindingError
            }
        }
        'InterfaceMetric' {
            $arguments = @{
                InterfaceIndex = $adapter.ifIndex; AddressFamily = $target.family; PolicyStore = 'ActiveStore'
                AutomaticMetric = $State.automaticMetric; ErrorAction = 'Stop'; Confirm = $false
            }
            if ($State.automaticMetric -eq 'Disabled') { $arguments.InterfaceMetric = $State.interfaceMetric }
            Set-NetIPInterface @arguments
        }
        'DnsServers' {
            $objects = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $target.family -ErrorAction Stop)
            if ($objects.Count -ne 1) { throw 'DNS family selection is ambiguous.' }
            if ($State.automatic) {
                Set-DnsClientServerAddress -InputObject $objects[0] -ResetServerAddresses -Confirm:$false -ErrorAction Stop
            } else {
                Set-DnsClientServerAddress -InputObject $objects[0] -ServerAddresses $State.servers -Confirm:$false -ErrorAction Stop
            }
        }
        'UserProxy' {
            Assert-NetworkRepairProxyPolicy
            $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            if ($State.present) {
                New-ItemProperty -LiteralPath $path -Name ProxyEnable -Value ([int][bool]$State.enabled) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $path -Name ProxyEnable -ErrorAction Stop
            }
            if (-not ('NetworkRepair.WinInet' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace NetworkRepair {
    public static class WinInet {
        [DllImport("wininet.dll", SetLastError=true)]
        public static extern bool InternetSetOption(IntPtr handle, int option, IntPtr buffer, int length);
    }
}
'@
            }
            if (-not [NetworkRepair.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) -or
                -not [NetworkRepair.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)) { throw 'WinINET notification failed.' }
        }
        'FirewallProfile' {
            Set-NetFirewallProfile -Name $target.profile -PolicyStore PersistentStore -Enabled $State.enabled `
                -LogBlocked $State.logBlocked -Confirm:$false -ErrorAction Stop
        }
        { $_ -in @('FirewallBlock','FirewallBlockAddress') } {
            if ($State.present) {
                $arguments = @{
                    Name=$RuleName; DisplayName=$RuleName; Description=$State.description; PolicyStore='PersistentStore'
                    RemoteAddress=$State.remoteAddress; Direction=$State.direction; Action='Block'; Enabled='True'; Profile='Any'
                    Confirm=$false; ErrorAction='Stop'
                }
                if ($Request.kind -eq 'FirewallBlock') { $arguments.Program = $State.program }
                New-NetFirewallRule @arguments | Out-Null
            } else {
                Get-NetFirewallRule -Name $RuleName -PolicyStore PersistentStore -ErrorAction Stop |
                    Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop
            }
        }
    }
}

function Get-NetworkRepairRouteDecision {
    param([System.Collections.IDictionary]$Request, [System.Collections.IDictionary]$State, [int]$CurrentCount)
    if ($CurrentCount -gt 1) { Stop-NetworkRepairForDrift 'Route became ambiguous.' }
    if ($State.present) {
        if ($Request.kind -eq 'RouteAdd') {
            if ($CurrentCount) { Stop-NetworkRepairForDrift 'Route appeared after the plan preflight.' }
            return 'Create'
        }
        if ($Request.kind -eq 'RouteRemove') {
            if ($CurrentCount) { Stop-NetworkRepairForDrift 'Route reappeared before restore; refusing to overwrite it.' }
            return 'Create'
        }
        if ($CurrentCount -ne 1) { Stop-NetworkRepairForDrift 'Expected exactly one route for update or restore.' }
        return 'UpdateMetric'
    }
    if ($CurrentCount -ne 1) { Stop-NetworkRepairForDrift 'Expected exactly one route for removal or restore.' }
    return 'Remove'
}

function Stop-NetworkRepairForDrift {
    param([string]$Reason)
    $failure = [InvalidOperationException]::new($Reason)
    $failure.Data['ManualRecoveryRequired'] = $true
    throw $failure
}

function Test-NetworkRepairStateEqual {
    param([System.Collections.IDictionary]$Request, [System.Collections.IDictionary]$Left, [System.Collections.IDictionary]$Right)
    if ($Request.kind -eq 'InterfaceMetric' -and $Left.automaticMetric -eq 'Enabled' -and $Right.automaticMetric -eq 'Enabled') { return $true }
    if ($Request.kind -in @('FirewallBlock','FirewallBlockAddress') -and $Left.present -and $Right.present) {
        if ($null -ne $Right.guardHash -and $Left.guardHash -cne $Right.guardHash) { return $false }
        $leftCopy = Copy-NetworkRepairValue $Left
        $rightCopy = Copy-NetworkRepairValue $Right
        $leftCopy.guardHash = $null
        $rightCopy.guardHash = $null
        return (Get-NetworkRepairDigest $leftCopy) -ceq (Get-NetworkRepairDigest $rightCopy)
    }
    (Get-NetworkRepairDigest $Left) -ceq (Get-NetworkRepairDigest $Right)
}

function New-NetworkRepairPlan {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Request, [ValidateRange(1,30)][int]$LifetimeMinutes = 10)
    Assert-NetworkRepairRequest $Request
    $identity = Get-NetworkRepairIdentity
    $ruleName = "CodexNetwork-$([guid]::NewGuid())"
    $before = Get-NetworkRepairState $Request $ruleName
    $desired = Get-NetworkRepairDesired $Request $before $ruleName
    if (Test-NetworkRepairStateEqual $Request $before $desired) { throw 'Requested state is already present.' }
    $plan = [ordered]@{
        version = '1.0.0'; id = "repair-$([guid]::NewGuid())"; createdAt = [DateTimeOffset]::UtcNow.ToString('o')
        expiresAt = [DateTimeOffset]::UtcNow.AddMinutes($LifetimeMinutes).ToString('o')
        identity = $identity; request = $Request; ruleName = $ruleName; before = $before; desired = $desired
        programHash = if ($Request.kind -eq 'FirewallBlock') { (Get-FileHash -LiteralPath $Request.target.program -Algorithm SHA256).Hash } else { $null }
        planHash = ''
    }
    $plan.planHash = Get-NetworkRepairDigest $plan
    $plan
}

function Assert-NetworkRepairPlan {
    param([System.Collections.IDictionary]$Plan, [string]$ApprovedPlanHash, [switch]$ForRollback)
    Assert-NetworkRepairKeys $Plan @('version','id','createdAt','expiresAt','identity','request','ruleName','before','desired','programHash','planHash')
    if ($Plan.version -cne '1.0.0' -or $Plan.id -notmatch '^repair-[0-9a-f-]{36}$' -or
        $Plan.ruleName -notmatch '^CodexNetwork-[0-9a-f-]{36}$' -or $ApprovedPlanHash -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid repair plan identity or approval digest.' }
    $copy = Copy-NetworkRepairValue $Plan
    $copy.planHash = ''
    if ($Plan.planHash -cne $ApprovedPlanHash -or (Get-NetworkRepairDigest $copy) -cne $ApprovedPlanHash) { throw 'Plan digest mismatch.' }
    Assert-NetworkRepairRequest $Plan.request -AllowMissingProgram:$ForRollback
    $derived = Get-NetworkRepairDesired $Plan.request $Plan.before $Plan.ruleName
    if ((Get-NetworkRepairDigest $derived) -cne (Get-NetworkRepairDigest $Plan.desired)) { throw 'Plan desired state is inconsistent.' }
    if ((Get-NetworkRepairDigest (Get-NetworkRepairIdentity)) -cne (Get-NetworkRepairDigest $Plan.identity)) { throw 'Plan machine or user changed.' }
    if (-not $ForRollback -and [DateTimeOffset]::UtcNow -gt [DateTimeOffset]::Parse($Plan.expiresAt)) { throw 'Repair plan expired; re-plan.' }
    if (-not $ForRollback -and $Plan.request.kind -eq 'FirewallBlock' -and
        (Get-FileHash -LiteralPath $Plan.request.target.program -Algorithm SHA256).Hash -cne $Plan.programHash) { throw 'Program bytes changed.' }
}

function Initialize-NetworkRepairDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $full = Assert-NetworkSafePath $Path
    [IO.Directory]::CreateDirectory($full) | Out-Null
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $full -AclObject $security -ErrorAction Stop
    $full
}

function Add-NetworkRepairEvent {
    param([string]$Directory, [System.Collections.IDictionary]$Plan, [string]$State, [AllowNull()][object]$Observed)
    $events = @(Read-NetworkRepairEvents $Directory $Plan)
    $event = [ordered]@{
        sequence = $events.Count; planHash = $Plan.planHash; state = $State; at = [DateTimeOffset]::UtcNow.ToString('o')
        previousHash = if ($events.Count) { $events[-1].eventHash } else { $null }
        observed = $Observed; eventHash = ''
    }
    $event.eventHash = Get-NetworkRepairDigest $event
    Write-NetworkJson -Path (Join-Path $Directory ('{0:D6}.json' -f $event.sequence)) -Object $event
}

function Read-NetworkRepairEvents {
    param([string]$Directory, [System.Collections.IDictionary]$Plan)
    $previous = $null
    $sequence = 0
    foreach ($file in @(Get-ChildItem -LiteralPath (Assert-NetworkSafePath $Directory) -File -ErrorAction Stop |
        Where-Object Name -Match '^\d{6}\.json$' | Sort-Object Name)) {
        if ($file.Name -cne ('{0:D6}.json' -f $sequence)) { throw 'Repair journal sequence gap.' }
        $event = Read-NetworkRepairJson $file.FullName
        Assert-NetworkRepairKeys $event @('sequence','planHash','state','at','previousHash','observed','eventHash')
        $hash = $event.eventHash
        $event.eventHash = ''
        if ($event.sequence -ne $sequence -or $event.previousHash -cne $previous -or $event.planHash -cne $Plan.planHash -or
            (Get-NetworkRepairDigest $event) -cne $hash) { throw 'Repair journal integrity failure.' }
        $event.eventHash = $hash
        $previous = $hash
        $sequence++
        $event
    }
}

function Get-NetworkProductionRepairRoot {
    Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'CodexNetworkRepair'
}

function Assert-NetworkRepairRootSettled {
    param([string]$Root, [string]$Except = '')
    foreach ($directory in @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop | Where-Object Name -Match '^repair-[0-9a-f-]{36}$')) {
        if ($directory.Name -ceq $Except) { continue }
        $plan = Read-NetworkRepairJson (Join-Path $directory.FullName 'plan.json')
        $events = @(Read-NetworkRepairEvents $directory.FullName $plan)
        if (-not $events.Count -or $events[-1].state -notin @('COMMITTED','ROLLED_BACK','ABORTED')) {
            throw "Unsettled repair freezes new writes: $($directory.Name)"
        }
    }
}

function Test-NetworkRepairEffectiveFirewall {
    param([System.Collections.IDictionary]$Plan)
    if ($Plan.request.kind -eq 'FirewallProfile') {
        $effective = @(Get-NetFirewallProfile -Name $Plan.request.target.profile -PolicyStore ActiveStore -ErrorAction Stop)
        if ($effective.Count -ne 1 -or [string]$effective[0].Enabled -ne 'True' -or [string]$effective[0].LogBlocked -ne 'True') {
            throw 'Effective firewall policy did not accept local protection settings.'
        }
    }
    if ($Plan.request.kind -in @('FirewallBlock','FirewallBlockAddress')) {
        $effective = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object Name -CEQ $Plan.ruleName)
        if ($effective.Count -ne 1 -or [string]$effective[0].Action -ne 'Block' -or [string]$effective[0].Enabled -ne 'True' -or
            [string]$effective[0].PrimaryStatus -ne 'OK') {
            throw 'Owned block rule is not effective; policy may reject or disable local rules.'
        }
        $activeCategories = @(Get-NetConnectionProfile -ErrorAction Stop | Select-Object -ExpandProperty NetworkCategory -Unique)
        if (-not $activeCategories.Count) { throw 'No active network profile could be verified for the block rule.' }
        foreach ($category in $activeCategories) {
            $profileName = switch ([string]$category) { 'DomainAuthenticated' {'Domain'} 'Private' {'Private'} 'Public' {'Public'} default {throw 'Unknown active network category.'} }
            $profile = @(Get-NetFirewallProfile -Name $profileName -PolicyStore ActiveStore -ErrorAction Stop)
            if ($profile.Count -ne 1 -or [string]$profile[0].Enabled -ne 'True') {
                throw "Firewall profile $profileName is disabled; the block rule is not enforced."
            }
        }
    }
}

function Get-NetworkRepairTargetKey {
    param([System.Collections.IDictionary]$Request)
    $scope = switch -CaseSensitive ([string]$Request.kind) {
        { $_ -in @('RouteMetric','RouteAdd','RouteRemove') } { 'route' }
        'InterfaceMetric' { 'interface-metric' }
        'DnsServers' { 'dns' }
        'UserProxy' { 'user-proxy' }
        'FirewallProfile' { 'firewall-profile' }
        'FirewallBlock' { "firewall-block:$($Request.target.program.ToLowerInvariant()):$($Request.target.remoteAddress)" }
        'FirewallBlockAddress' { "firewall-block-address:$($Request.target.remoteAddress)" }
        default { throw 'Unknown target kind.' }
    }
    $target = Copy-NetworkRepairValue $Request.target
    if ($target.Contains('interfaceGuid')) { $target.interfaceGuid = ([guid]$target.interfaceGuid).ToString('D') }
    if ($target.Contains('nextHop')) { $target.nextHop = [Net.IPAddress]::Parse($target.nextHop).ToString() }
    if ($target.Contains('destinationPrefix')) {
        $parts = $target.destinationPrefix.Split('/')
        $target.destinationPrefix = [Net.IPAddress]::Parse($parts[0]).ToString() + '/' + [int]$parts[1]
    }
    $identity = [ordered]@{scope=$scope;target=$target}
    Get-NetworkRepairDigest $identity
}

function Assert-NetworkNoLaterRepair {
    param([string]$Root, [System.Collections.IDictionary]$Plan, [string]$CurrentDirectory)
    $key = Get-NetworkRepairTargetKey $Plan.request
    $ownEvents = @(Read-NetworkRepairEvents (Join-Path $Root $CurrentDirectory) $Plan)
    if (-not $ownEvents.Count) { throw 'Current transaction has no start event.' }
    $started = [DateTimeOffset]::Parse($ownEvents[0].at)
    foreach ($directory in @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '^repair-[0-9a-f-]{36}$' -and $_.Name -cne $CurrentDirectory })) {
        $otherPlanPath = Join-Path $directory.FullName 'plan.json'
        if (-not (Test-Path -LiteralPath $otherPlanPath -PathType Leaf)) { continue }
        $other = Read-NetworkRepairJson $otherPlanPath
        if ($other.request.kind -in @('FirewallBlock','FirewallBlockAddress')) { continue }
        if ((Get-NetworkRepairTargetKey $other.request) -cne $key) { continue }
        $events = @(Read-NetworkRepairEvents $directory.FullName $other)
        if (-not $events.Count -or [DateTimeOffset]::Parse($events[0].at) -le $started) { continue }
        $state = if ($events.Count) { $events[-1].state } else { 'NOT_STARTED' }
        if ($state -ne 'ROLLED_BACK') { throw 'A later transaction owns or may have altered this resource.' }
    }
}

function Invoke-NetworkRepairRollbackCore {
    param([System.Collections.IDictionary]$Plan, [string]$Directory)
    $now = Get-NetworkRepairState $Plan.request $Plan.ruleName
    if (Test-NetworkRepairStateEqual $Plan.request $now $Plan.before) {
        Add-NetworkRepairEvent $Directory $Plan 'ROLLED_BACK' $now
        return 'ROLLED_BACK'
    }
    $rollbackExpected = Copy-NetworkRepairValue $Plan.desired
    if ($Plan.request.kind -in @('FirewallBlock','FirewallBlockAddress') -and $now.present) {
        $observedEvents = @(Read-NetworkRepairEvents $Directory $Plan | Where-Object {
            $_.state -in @('VALIDATING','COMMITTED') -and $null -ne $_.observed -and $_.observed.Contains('guardHash')
        })
        if (-not $observedEvents.Count) {
            Add-NetworkRepairEvent $Directory $Plan 'MANUAL_RECOVERY_REQUIRED' $now
            return 'MANUAL_RECOVERY_REQUIRED'
        }
        $rollbackExpected.guardHash = $observedEvents[-1].observed.guardHash
    }
    if (-not (Test-NetworkRepairStateEqual $Plan.request $now $rollbackExpected)) {
        Add-NetworkRepairEvent $Directory $Plan 'MANUAL_RECOVERY_REQUIRED' $now
        return 'MANUAL_RECOVERY_REQUIRED'
    }
    Add-NetworkRepairEvent $Directory $Plan 'ROLLING_BACK' $now
    $fresh = Get-NetworkRepairState $Plan.request $Plan.ruleName
    if (-not (Test-NetworkRepairStateEqual $Plan.request $fresh $rollbackExpected)) { throw 'State drifted before rollback.' }
    Set-NetworkRepairState $Plan.request $Plan.before $Plan.ruleName -ExpectedState $fresh
    $restored = Get-NetworkRepairState $Plan.request $Plan.ruleName
    if (-not (Test-NetworkRepairStateEqual $Plan.request $restored $Plan.before)) { throw 'Rollback readback mismatch.' }
    Add-NetworkRepairEvent $Directory $Plan 'ROLLED_BACK' $restored
    'ROLLED_BACK'
}

function Invoke-NetworkProductionRepair {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$PlanPath, [Parameter(Mandatory)][string]$ApprovedPlanHash,
        [ValidateSet('apply','rollback','repair-status')][string]$Intent = 'apply')
    $plan = Read-NetworkRepairJson $PlanPath
    Assert-NetworkRepairPlan $plan $ApprovedPlanHash -ForRollback:($Intent -ne 'apply')
    $root = Get-NetworkProductionRepairRoot
    $directory = Join-Path $root $plan.id
    if ($Intent -eq 'repair-status') {
        $events = @(Read-NetworkRepairEvents $directory $plan)
        $now = Get-NetworkRepairState $plan.request $plan.ruleName
        return @{
            status = if ($events.Count) { $events[-1].state } else { 'NOT_STARTED' }
            current = $now; equalsBefore = (Test-NetworkRepairStateEqual $plan.request $now $plan.before)
            equalsDesired = (Test-NetworkRepairStateEqual $plan.request $now $plan.desired)
            safeToReplay = $false; transactionDirectory = $directory; networkChanges = $false
        }
    }
    if (-not (Test-NetworkAdministratorToken)) { throw 'An elevated administrator token is required.' }
    if (-not $PSCmdlet.ShouldProcess("$($plan.request.kind) $($plan.id)", $Intent)) {
        return @{ status = 'NOT_RUN'; networkChanges = $false; planHash = $plan.planHash }
    }
    $mutex = [Threading.Mutex]::new($false, 'Global\CodexWindowsNetworkRepair-v1')
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { throw 'Another network repair writer is active.' }
        $null = Initialize-NetworkRepairDirectory $root
        if ($Intent -eq 'rollback') {
            Assert-NetworkRepairRootSettled $root $plan.id
            $saved = Read-NetworkRepairJson (Join-Path $directory 'plan.json')
            Assert-NetworkRepairPlan $saved $ApprovedPlanHash -ForRollback
            $events = @(Read-NetworkRepairEvents $directory $saved)
            if (-not $events.Count) { throw 'No write-ahead repair journal exists.' }
            if ($events[-1].state -eq 'ROLLED_BACK') { throw 'This transaction already reached ROLLED_BACK and cannot write again.' }
            Assert-NetworkNoLaterRepair $root $saved $saved.id
            try { $status = Invoke-NetworkRepairRollbackCore $saved $directory }
            catch {
                Add-NetworkRepairEvent $directory $saved 'MANUAL_RECOVERY_REQUIRED' @{ code = $_.Exception.GetType().Name }
                $status = 'MANUAL_RECOVERY_REQUIRED'
            }
            return @{ status = $status; transactionDirectory = $directory; networkChanges = $true; validation = 'configuration readback' }
        }
        Assert-NetworkRepairRootSettled $root
        if (Test-Path -LiteralPath $directory) { throw 'This plan was already started; use repair-status or rollback.' }
        $now = Get-NetworkRepairState $plan.request $plan.ruleName
        if (-not (Test-NetworkRepairStateEqual $plan.request $now $plan.before)) { throw 'Before-state drift; regenerate plan.' }
        $null = Initialize-NetworkRepairDirectory $directory
        Write-NetworkJson -Path (Join-Path $directory 'plan.json') -Object $plan
        Add-NetworkRepairEvent $directory $plan 'PREPARED' $now
        try {
            Assert-NetworkRepairPlan $plan $ApprovedPlanHash
            $fresh = Get-NetworkRepairState $plan.request $plan.ruleName
            if (-not (Test-NetworkRepairStateEqual $plan.request $fresh $plan.before)) { Stop-NetworkRepairForDrift 'State drifted before write.' }
            Add-NetworkRepairEvent $directory $plan 'APPLYING' $fresh
            Set-NetworkRepairState $plan.request $plan.desired $plan.ruleName -ExpectedState $fresh
            $after = Get-NetworkRepairState $plan.request $plan.ruleName
            Add-NetworkRepairEvent $directory $plan 'VALIDATING' $after
            if (-not (Test-NetworkRepairStateEqual $plan.request $after $plan.desired)) { throw 'Repair readback mismatch.' }
            Test-NetworkRepairEffectiveFirewall $plan
            Start-Sleep -Milliseconds 250
            $settled = Get-NetworkRepairState $plan.request $plan.ruleName
            if (-not (Test-NetworkRepairStateEqual $plan.request $settled $after)) { throw 'An external writer changed the resource.' }
            Add-NetworkRepairEvent $directory $plan 'COMMITTED' $settled
            @{ status = 'COMMITTED'; transactionDirectory = $directory; planHash = $plan.planHash; networkChanges = $true; validation = 'configuration readback; end-to-end connectivity NOT_RUN' }
        } catch {
            $mutationError = $_.Exception
            Add-NetworkRepairEvent $directory $plan 'FAILED' @{ code = $_.Exception.GetType().Name }
            try {
                if ($mutationError.Data.Contains('ManualRecoveryRequired')) {
                    Add-NetworkRepairEvent $directory $plan 'MANUAL_RECOVERY_REQUIRED' @{ code = 'AdapterBindingChanged' }
                    $status = 'MANUAL_RECOVERY_REQUIRED'
                } else { $status = Invoke-NetworkRepairRollbackCore $plan $directory }
            }
            catch {
                Add-NetworkRepairEvent $directory $plan 'MANUAL_RECOVERY_REQUIRED' @{ code = $_.Exception.GetType().Name }
                $status = 'MANUAL_RECOVERY_REQUIRED'
            }
            @{ status = $status; applySucceeded = $false; transactionDirectory = $directory; networkChanges = $true; failure = 'Apply or validation failed; inspect journal and independent observations.' }
        }
    } finally {
        if ($locked) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

Export-ModuleMember -Function *-Network*
