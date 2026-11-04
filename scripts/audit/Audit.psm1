#Requires -Version 7.4
Set-StrictMode -Version Latest

function Get-NetworkExtendedCollectors {
    $collectors = [ordered]@{
        proxySettings = {
            $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            $properties = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            $safe = [ordered]@{}
            foreach ($name in @('ProxyEnable','ProxyServer','AutoConfigURL','AutoDetect')) {
                $property = $properties.PSObject.Properties[$name]
                $safe[$name] = @{
                    present=($null -ne $property)
                    fingerprint=if ($property) { Get-NetworkHash ([string]$property.Value) } else { $null }
                }
            }
            $safe
        }
        proxyClients = {
            foreach ($process in @(Get-Process -ErrorAction Stop | Where-Object {
                $_.ProcessName -match '^(FlClash|FlClashCore|FlClashHelperService|mihomo|clash.*|v2rayN|v2ray|xray|sing-box|NekoRay|Hiddify|warp-svc|openvpn|wireguard.*|tailscaled|zerotier-one.*)$'
            })) {
                try {
                    @{ name = $process.ProcessName; processId = $process.Id; startTicks = $process.StartTime.ToUniversalTime().Ticks; path = $process.Path; pathStatus = 'OBSERVED' }
                } catch {
                    @{ name = $process.ProcessName; processId = $process.Id; startTicks = $null; path = $null; pathStatus = 'BLOCKED' }
                } finally { $process.Dispose() }
            }
        }
        tcp = {
            $items = @(Get-NetTCPConnection -ErrorAction Stop | Sort-Object OwningProcess,LocalPort,RemoteAddress,RemotePort)
            @{ total = $items.Count; truncated = ($items.Count -gt 4096); items = @($items | Select-Object -First 4096 LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,@{n='State';e={[string]$_.State}}) }
        }
        udp = {
            $items = @(Get-NetUDPEndpoint -ErrorAction Stop | Sort-Object OwningProcess,LocalPort,LocalAddress)
            @{ total = $items.Count; truncated = ($items.Count -gt 4096); items = @($items | Select-Object -First 4096 LocalAddress,LocalPort,OwningProcess) }
        }
        firewallProfiles = {
            foreach ($store in @('ActiveStore','PersistentStore')) {
                Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop | Select-Object Name,@{n='Store';e={$store}},
                    @{n='Enabled';e={[string]$_.Enabled}},@{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}},
                    @{n='DefaultOutboundAction';e={[string]$_.DefaultOutboundAction}},@{n='LogBlocked';e={[string]$_.LogBlocked}},
                    @{n='AllowLocalFirewallRules';e={[string]$_.AllowLocalFirewallRules}}
            }
        }
        firewallRules = {
            $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop |
                Where-Object { [string]$_.Enabled -eq 'True' } | Sort-Object Name)
            @{ total = $rules.Count; truncated = ($rules.Count -gt 2048); items = @($rules | Select-Object -First 2048 Name,InstanceID,
                @{n='Direction';e={[string]$_.Direction}},@{n='Action';e={[string]$_.Action}},@{n='Profile';e={[string]$_.Profile}},
                PolicyStoreSourceType,PolicyStoreSource,PrimaryStatus) }
        }
        firewallApplications = {
            $filters = @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -ErrorAction Stop)
            @{total=$filters.Count;truncated=($filters.Count -gt 4096);items=@($filters | Select-Object -First 4096 InstanceID,Program,Package)}
        }
        firewallPorts = {
            $filters = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop)
            @{total=$filters.Count;truncated=($filters.Count -gt 4096);items=@($filters | Select-Object -First 4096 InstanceID,Protocol,LocalPort,RemotePort)}
        }
        firewallAddresses = {
            $filters = @(Get-NetFirewallAddressFilter -PolicyStore ActiveStore -ErrorAction Stop)
            @{total=$filters.Count;truncated=($filters.Count -gt 4096);items=@($filters | Select-Object -First 4096 InstanceID,LocalAddress,RemoteAddress)}
        }
        defender = {
            Get-CimInstance -Namespace 'root/Microsoft/Windows/Defender' -ClassName MSFT_MpComputerStatus -ErrorAction Stop |
                Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,
                    NISEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime,IsTamperProtected
        }
        defenderDetections = {
            Get-CimInstance -Namespace 'root/Microsoft/Windows/Defender' -ClassName MSFT_MpThreatDetection -ErrorAction Stop |
                Select-Object ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess,CurrentThreatExecutionStatusID,ThreatStatusID
        }
        networkEvents = {
            $start = [DateTime]::Now.AddHours(-2)
            foreach ($channel in @('Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-DNS-Client/Operational',
                'Microsoft-Windows-NetworkProfile/Operational','Microsoft-Windows-WLAN-AutoConfig/Operational')) {
                try {
                    $exists = Get-WinEvent -ListLog $channel -ErrorAction Stop
                    if (-not $exists.IsEnabled) { @{ log = $channel; status = 'DISABLED'; count = $null }; continue }
                    $events = @(Get-WinEvent -FilterHashtable @{LogName=$channel;StartTime=$start} -MaxEvents 256 -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
                    $unexpected = @($queryErrors | Where-Object FullyQualifiedErrorId -NotLike 'NoMatchingEventsFound*')
                    if ($unexpected.Count) { throw 'Event log access failed.' }
                    @{ log = $channel; status = 'PASS'; capped = ($events.Count -eq 256); events = @($events | Select-Object Id,Level,TimeCreated,RecordId,ProviderName) }
                } catch { @{log=$channel;status='BLOCKED';errorCode=$_.Exception.GetType().Name;events=$null} }
            }
        }
        securityEvents = {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=@(4625,5152,5157); StartTime=[DateTime]::Now.AddHours(-2) } `
                -MaxEvents 512 -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
            $unexpected = @($queryErrors | Where-Object FullyQualifiedErrorId -NotLike 'NoMatchingEventsFound*')
            if ($unexpected.Count) { throw 'Security log is unreadable.' }
            @{ capped = ($events.Count -eq 512); events = @($events | Select-Object Id,Level,TimeCreated,RecordId) }
        }
        winhttp = {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
            $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            $value = $item.PSObject.Properties['WinHttpSettings']
            @{ binarySettingsPresent = ($null -ne $value); settingsHash = if ($value) {
                [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$value.Value)).ToLowerInvariant()
            } else { $null }; interpretation = 'Binary presence/hash only; not a proxy endpoint or direct-mode verdict.' }
        }
        hosts = {
            $file = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            $lines = @([IO.File]::ReadAllLines($file) | Where-Object { $_ -notmatch '^\s*(#|$)' })
            @{ sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash; activeLineCount = $lines.Count; contentOmitted = $true }
        }
        networkServices = {
            Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
                $_.Name -match '^(BFE|MpsSvc|Dhcp|Dnscache|NlaSvc|WinHttpAutoProxySvc|WinDefend|FlClash.*|mihomo.*|clash.*|sing-box.*)$'
            } | Select-Object Name,State,StartMode,ProcessId
        }
    }
    $collectors
}

function Get-NetworkAuditBundles {
    param([hashtable]$Context, [switch]$IncludeSecurity)
    $bundles = Get-NetworkDiscovery -Context $Context
    $collectors = Get-NetworkExtendedCollectors
    foreach ($key in $collectors.Keys) {
        if (-not $IncludeSecurity -and $key -notin @('proxySettings','proxyClients','tcp','udp','winhttp','networkServices')) { continue }
        $bundles[$key] = Invoke-NetworkRead -Name "extended/$key" -Context $Context -Read $collectors[$key]
    }
    if ($IncludeSecurity -and $bundles.tcp.record.collectionStatus -eq 'PASS') {
        $owners = @($bundles.tcp.data | ForEach-Object { $_.items } | Select-Object -ExpandProperty OwningProcess -Unique | Sort-Object)
        $bundles.networkOwners = Invoke-NetworkRead -Name 'TCP owner process identity, bounded to 256 IDs' -Context $Context -Read {
            foreach ($ownerId in @($owners | Select-Object -First 256)) {
                try {
                    $process = Get-Process -Id $ownerId -ErrorAction Stop
                    try {
                        @{processId=$ownerId;status='OBSERVED';name=$process.ProcessName;startTicks=$process.StartTime.ToUniversalTime().Ticks;path=$process.Path}
                    } finally { $process.Dispose() }
                } catch { @{processId=$ownerId;status='UNKNOWN';name=$null;startTicks=$null;path=$null} }
            }
        }
    }
    $bundles
}

function New-NetworkAuditFinding {
    param([string]$Code, [string]$Severity, [string]$Observation, [string]$Next, [string[]]$EvidenceIds)
    @{
        id = "finding-$([guid]::NewGuid())"; code = $Code; severity = $Severity
        classification = 'OBSERVED_OR_HYPOTHESIS'; observation = $Observation; next = $Next
        evidenceIds = @($EvidenceIds); provesAttack = $false
    }
}

function Get-NetworkAuditFindings {
    param([System.Collections.IDictionary]$Bundles)
    $findings = [Collections.Generic.List[object]]::new()
    foreach ($key in $Bundles.Keys) {
        if ($Bundles[$key].record.collectionStatus -ne 'PASS') {
            $findings.Add((New-NetworkAuditFinding "COLLECTION_$key" 'unknown' "$key unavailable; absence is not established." `
                'Check collector availability and token permissions; keep UNKNOWN.' @($Bundles[$key].record.id)))
        }
    }
    if ($Bundles.Contains('proxyClients') -and $Bundles.proxyClients.record.collectionStatus -eq 'PASS') {
        $clients = @($Bundles.proxyClients.data | Where-Object name -NotMatch '(Core|HelperService|clash|mihomo|xray|v2ray|sing-box)$')
        if ($clients.Count -gt 1) {
            $findings.Add((New-NetworkAuditFinding 'MULTIPLE_PROXY_CLIENTS' 'review' 'Several proxy/VPN clients are running; simultaneous configuration ownership is a hypothesis.' `
                'Sample routes, DNS, proxy and listener owner changes; choose one owner through its supported UI.' @($Bundles.proxyClients.record.id)))
        }
    }
    if ($Bundles.addresses.record.collectionStatus -eq 'PASS') {
        foreach ($family in @('IPv4','IPv6')) {
            $addresses = @($Bundles.addresses.data | Where-Object AddressFamily -EQ $family)
            $invalid = @($addresses | Where-Object AddressState -In @('Duplicate','Tentative','Invalid'))
            if ($invalid.Count) {
                $findings.Add((New-NetworkAuditFinding "${family}_ADDRESS_STATE" 'review' "$family has Duplicate/Tentative/Invalid addresses." `
                    'Match adapter GUID, DAD, DHCP/RA and event timestamps; do not disable the whole address family.' @($Bundles.addresses.record.id)))
            }
            if ($family -eq 'IPv4' -and @($addresses | Where-Object IPAddress -Like '169.254.*').Count) {
                $findings.Add((New-NetworkAuditFinding 'IPV4_APIPA' 'review' 'APIPA exists on at least one adapter; this does not prove whole-host failure.' `
                    'Check link, DHCP lease and the intended physical adapter.' @($Bundles.addresses.record.id)))
            }
        }
    }
    if ($Bundles.routes.record.collectionStatus -eq 'PASS') {
        foreach ($family in @('IPv4','IPv6')) {
            $prefix = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
            $defaults = @($Bundles.routes.data | Where-Object { $_.AddressFamily -eq $family -and $_.DestinationPrefix -eq $prefix -and $_.Store -eq 'ActiveStore' })
            if (-not $defaults.Count) {
                $findings.Add((New-NetworkAuditFinding "${family}_DEFAULT_NOT_OBSERVED" 'review' "$family default route was not observed in the collector compartment." `
                    'Check split TUN routes, destination route, RA/DHCP and other compartments before creating a route.' @($Bundles.routes.record.id)))
            }
        }
    }
    if ($Bundles.Contains('firewallProfiles') -and $Bundles.firewallProfiles.record.collectionStatus -eq 'PASS') {
        foreach ($profile in @($Bundles.firewallProfiles.data | Where-Object Store -EQ ActiveStore)) {
            if ($profile.Enabled -eq 'False') {
                $findings.Add((New-NetworkAuditFinding 'FIREWALL_DISABLED' 'high' "Effective $($profile.Name) firewall profile is disabled." `
                    'Establish local/domain policy ownership; plan FirewallProfile enablement and verify effective policy.' @($Bundles.firewallProfiles.record.id)))
            }
            if ($profile.DefaultInboundAction -eq 'Allow') {
                $findings.Add((New-NetworkAuditFinding 'INBOUND_DEFAULT_ALLOW' 'high' "Effective $($profile.Name) default inbound action is Allow." `
                    'Review required inbound services and GPO. Apply an approved profile policy; avoid blind rule resets.' @($Bundles.firewallProfiles.record.id)))
            }
        }
    }
    if ($Bundles.Contains('firewallRules') -and $Bundles.Contains('firewallApplications') -and
        $Bundles.Contains('firewallAddresses') -and $Bundles.firewallRules.record.collectionStatus -eq 'PASS' -and
        $Bundles.firewallApplications.record.collectionStatus -eq 'PASS' -and $Bundles.firewallAddresses.record.collectionStatus -eq 'PASS') {
        $applications = @{}
        foreach ($filter in @($Bundles.firewallApplications.data | ForEach-Object { $_.items })) { $applications[[string]$filter.InstanceID] = $filter }
        $addresses = @{}
        foreach ($filter in @($Bundles.firewallAddresses.data | ForEach-Object { $_.items })) { $addresses[[string]$filter.InstanceID] = $filter }
        $broad = @($Bundles.firewallRules.data | ForEach-Object { $_.items } | Where-Object {
            $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and
            $applications.ContainsKey([string]$_.InstanceID) -and $addresses.ContainsKey([string]$_.InstanceID) -and
            [string]$applications[[string]$_.InstanceID].Program -eq 'Any' -and
            @($addresses[[string]$_.InstanceID].RemoteAddress).Count -eq 1 -and
            [string]$addresses[[string]$_.InstanceID].RemoteAddress[0] -eq 'Any'
        })
        if ($broad.Count) {
            $findings.Add((New-NetworkAuditFinding 'BROAD_INBOUND_ALLOW_CANDIDATE' 'review' "$($broad.Count) inbound Allow rules have candidate Any-program/Any-remote filters." `
                'Resolve each rule through associated filter cmdlets, then inspect ports, services, profiles and policy source. Do not delete by display name.' `
                @($Bundles.firewallRules.record.id,$Bundles.firewallApplications.record.id,$Bundles.firewallAddresses.record.id)))
        }
    }
    if ($Bundles.Contains('tcp') -and $Bundles.tcp.record.collectionStatus -eq 'PASS') {
        foreach ($packet in $Bundles.tcp.data) {
            $exposed = @($packet.items | Where-Object {
                $_.State -eq 'Listen' -and $_.LocalAddress -in @('0.0.0.0','::') -and $_.LocalPort -in @(1080,7890,7891,7892,9090,3389,445,5985,5986)
            })
            if ($exposed.Count) {
                $findings.Add((New-NetworkAuditFinding 'WILDCARD_SENSITIVE_LISTENER' 'review' 'A proxy, controller or administration port listens on a wildcard address.' `
                    'Correlate owning PID/start time, executable, program firewall filters, profile and remote scope; listening does not prove external reachability.' @($Bundles.tcp.record.id)))
            }
        }
    }
    if ($Bundles.Contains('defenderDetections') -and $Bundles.defenderDetections.record.collectionStatus -eq 'PASS' -and
        @($Bundles.defenderDetections.data).Count) {
        $findings.Add((New-NetworkAuditFinding 'DEFENDER_DETECTION_HISTORY' 'high' 'Defender detection records exist; history is not proof of an active infection.' `
            'Check threat ID, action success, status and timestamps in Windows Security. Preserve evidence before remediation.' @($Bundles.defenderDetections.record.id)))
    }
    if ($Bundles.Contains('securityEvents') -and $Bundles.securityEvents.record.collectionStatus -eq 'PASS') {
        $count = @($Bundles.securityEvents.data | ForEach-Object { $_.events } | Where-Object Id -EQ 4625).Count
        if ($count -ge 20) {
            $findings.Add((New-NetworkAuditFinding 'FAILED_LOGON_BURST' 'review' "$count failed logons appear in the bounded two-hour sample." `
                'Locally inspect selected event fields and sources; distinguish stale credentials, service failures and hostile attempts.' @($Bundles.securityEvents.record.id)))
        }
    }
    @($findings)
}

function Save-NetworkAudit {
    param([System.Collections.IDictionary]$Bundles, [hashtable]$Context, [string]$StateRoot, [string]$SkillRoot)
    $run = New-NetworkRunDirectory -StateRoot $StateRoot -SkillRoot $SkillRoot
    foreach ($bundle in $Bundles.Values) {
        Write-NetworkJson -Path (Join-Path $run "evidence/$($bundle.record.id).json") -Object $bundle.record
        if ($bundle.record.collectionStatus -eq 'PASS') {
            Write-NetworkJson -Path (Join-Path $run "payload/$($bundle.record.id).json") -Object @($bundle.data)
        }
    }
    $findings = @(Get-NetworkAuditFindings $Bundles)
    Write-NetworkJson -Path (Join-Path $run 'findings.json') -Object $findings
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('# Windows 网络与安全审计')
    $lines.Add('')
    $lines.Add('只读取证。未证明正在遭受攻击，也未证明系统安全。采集非原子；失败项保留 UNKNOWN。')
    $lines.Add('')
    foreach ($finding in $findings) {
        $lines.Add("## $($finding.code) [$($finding.severity)]")
        $lines.Add('')
        $lines.Add($finding.observation)
        $lines.Add($finding.next)
        $lines.Add("Evidence: $($finding.evidenceIds -join ', ')")
        $lines.Add('')
    }
    $lines.Add('## 采集覆盖')
    $lines.Add('')
    foreach ($key in $Bundles.Keys) { $lines.Add("- ${key}: $($Bundles[$key].record.collectionStatus); $($Bundles[$key].record.id)") }
    Write-NetworkFile -Path (Join-Path $run 'report.md') -Text ($lines -join "`n")
    $hashes = @(Get-ChildItem -LiteralPath $run -File -Recurse | Sort-Object FullName | ForEach-Object {
        @{ file = [IO.Path]::GetRelativePath($run, $_.FullName); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
    Write-NetworkJson -Path (Join-Path $run 'audit-manifest.json') -Object @{
        version='1.0.0'; hostRef=$Context.hostRef; kind='audit'; files=$hashes; authentic=$false; observationOnly=$true
    }
    @{ status='PASS'; meaning='Audit artifacts saved; not an attack or health verdict.'; runDirectory=$run; report=(Join-Path $run 'report.md'); findings=$findings.Count; networkChanges=$false }
}

function Get-NetworkRaceProjection {
    param([System.Collections.IDictionary]$Bundles)
    $projection = [ordered]@{}
    foreach ($key in @('interfaces','routes','dns','proxies','proxySettings','proxyClients','winhttp')) {
        $bundle = $Bundles[$key]
        $projection[$key] = @{
            status = $bundle.record.collectionStatus
            fingerprint = if ($bundle.record.collectionStatus -eq 'PASS') {
                $items = @($bundle.data | ForEach-Object { ConvertTo-NetworkCanonicalJson $_ } | Sort-Object -CaseSensitive)
                Get-NetworkRepairDigest $items
            } else { $null }
            evidenceId = $bundle.record.id
        }
    }
    $listeners = $Bundles.tcp
    $projection.listeners = @{
        status = $listeners.record.collectionStatus
        fingerprint = if ($listeners.record.collectionStatus -eq 'PASS') {
            Get-NetworkRepairDigest @($listeners.data | ForEach-Object { $_.items } | Where-Object State -EQ Listen |
                Sort-Object LocalAddress,LocalPort,OwningProcess)
        } else { $null }
        evidenceId = $listeners.record.id
    }
    $projection
}

function Invoke-NetworkRaceWatch {
    param([string]$StateRoot, [string]$SkillRoot, [ValidateRange(2,120)][int]$Samples=6,
        [ValidateRange(100,10000)][int]$IntervalMilliseconds=500)
    if (($Samples - 1) * $IntervalMilliseconds -gt 120000) { throw 'Sampling sleep budget exceeds 120 seconds.' }
    $context = New-NetworkContext
    $run = New-NetworkRunDirectory -StateRoot $StateRoot -SkillRoot $SkillRoot
    $changes = [Collections.Generic.List[object]]::new()
    $previous = $null
    for ($index = 0; $index -lt $Samples; $index++) {
        $started = [DateTimeOffset]::UtcNow
        $bundles = Get-NetworkAuditBundles -Context $context
        $projection = Get-NetworkRaceProjection $bundles
        Write-NetworkJson -Path (Join-Path $run ("sample-{0:D3}.json" -f $index)) -Object @{
            index=$index; startedAt=$started.ToString('o'); endedAt=[DateTimeOffset]::UtcNow.ToString('o')
            projection=$projection; bundles=$bundles
        }
        if ($null -ne $previous) {
            foreach ($key in $projection.Keys) {
                $before = $previous[$key]; $after = $projection[$key]
                if ($before.status -ne $after.status -or $before.fingerprint -cne $after.fingerprint) {
                    $changes.Add(@{ sample=$index; section=$key; before=$before; after=$after; writer='UNKNOWN' })
                }
            }
        }
        $previous = $projection
        if ($index -lt $Samples - 1) { Start-Sleep -Milliseconds $IntervalMilliseconds }
    }
    Write-NetworkJson -Path (Join-Path $run 'changes.json') -Object @($changes)
    Write-NetworkFile -Path (Join-Path $run 'report.md') -Text @"
# Windows 网络竞态采样

Samples: $Samples. Requested sleep interval: $IntervalMilliseconds ms; actual interval also includes collector time.
Changed sections: $($changes.Count).

顺序采样不能捕获所有瞬时变化。状态差异不能单独证明写入者、因果或攻击。
代理端点只保存存在性和散列；不保存 PAC URL、代理地址或凭据。结合 WinHTTP hash、PID/start time、监听与路由继续核验。
完整记录见 sample-*.json 与 changes.json。网络未修改。
"@
    @{ status='PASS'; samples=$Samples; changes=$changes.Count; runDirectory=$run; report=(Join-Path $run 'report.md'); networkChanges=$false }
}

function Get-NetworkProcessEvidence {
    param([ValidateRange(1,2147483647)][int]$ProcessId)
    $process = Get-Process -Id $ProcessId -ErrorAction Stop
    try {
        $null = $process.Handle
        $ticks = $process.StartTime.ToUniversalTime().Ticks
        $path = $process.Path
        if (-not $path) { throw 'Executable path unavailable.' }
        $safePath = Assert-NetworkSafePath $path
        $file = Get-Item -LiteralPath $safePath -ErrorAction Stop
        if ($file.Length -gt 268435456) { throw 'Image exceeds the 256 MiB inspection limit.' }
        $hash = (Get-FileHash -LiteralPath $safePath -Algorithm SHA256).Hash
        $signature = Get-AuthenticodeSignature -LiteralPath $safePath -ErrorAction Stop
        $process.Refresh()
        if ($process.HasExited -or $process.StartTime.ToUniversalTime().Ticks -ne $ticks) { throw 'Process exited or identity changed.' }
        @{
            status='PASS'; processId=$ProcessId; startTicks=$ticks; path=$safePath; sha256=$hash
            signatureStatus=[string]$signature.Status
            signer=if ($signature.SignerCertificate) {$signature.SignerCertificate.Subject} else {$null}
            meaning='On-disk image evidence only; signature/hash do not prove memory integrity, reputation or safety.'
            networkChanges=$false
        }
    } finally { $process.Dispose() }
}

Export-ModuleMember -Function *-Network*
