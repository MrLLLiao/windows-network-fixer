#Requires -Version 7.4
Set-StrictMode -Version Latest

function New-NetworkBaseline {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Bundles,[Parameter(Mandatory)][hashtable]$Context)
    $ids=@($Bundles.Values | ForEach-Object {$_.record.id})
    $baseline=New-NetworkObject -Type NetworkBaseline -Context $Context -EvidenceIds $ids
    $times=@($Bundles.Values | ForEach-Object {$_.record.startedAt} | Sort-Object)
    $baseline.baselineWindow=@{start=$times[0];end=[DateTimeOffset]::Now.ToString('o')}
    foreach($name in @('environment','interfaces','addresses','routes','dns','proxies','ipInterfaces','nrpt','processes','listeners','dataDirectories')){$baseline[$name]=New-NetworkFact $Bundles[$name]}
    $baseline.flclash=@{classification='UNKNOWN';value=$null;evidenceIds=@($Bundles.processes.record.id,$Bundles.listeners.record.id);unknownReason='Client process and listeners do not establish authenticated runtime configuration.'}
    if($Bundles.Contains('apiversion') -and $Bundles.Contains('apiconfigs') -and $Bundles.apiversion.record.collectionStatus -eq 'PASS' -and $Bundles.apiconfigs.record.collectionStatus -eq 'PASS'){
        $baseline.flclash=@{classification='OBSERVED';value=@{version=$Bundles.apiversion.data;configs=$Bundles.apiconfigs.data;scope='verified loopback controller, selected fields only'};evidenceIds=@($Bundles.apiversion.record.id,$Bundles.apiconfigs.record.id);unknownReason=$null}
    }
    $baseline.capabilities=@('read-only','observation-snapshot','integrity-check','offline-fixture','transaction-journal-model','same-host-socket-probe','isolated-lab-harness');$baseline.consistency='unknown'
    $baseline.synthetic=$Context.synthetic
    $baseline
}
function Get-NetworkFamilyDiagnostics {
    param([Parameter(Mandatory)][object]$Baseline,[Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][ValidateSet('IPv4','IPv6')][string]$Family)
    $result=New-NetworkObject -Type DiagnosticResult -Context $Context -EvidenceIds @($Baseline.addresses.evidenceIds+$Baseline.routes.evidenceIds+$Baseline.interfaces.evidenceIds)
    $result.layer='L3';$result.family=$Family;$result.resource=New-NetworkResource -Family $Family
    $result.hypothesis=$null;$result.rootCause=$null;$result.confidence='insufficient';$result.tests=@();$result.excluded=@()
    $result.openQuestions=@('Native route and packet path have not been independently verified.','TCP/TLS and proxy egress have not been tested.','RA/DHCP and upstream capability require separate evidence.')
    if($Baseline.addresses.classification -eq 'UNKNOWN' -or $Baseline.routes.classification -eq 'UNKNOWN' -or $Baseline.interfaces.classification -eq 'UNKNOWN'){
        $result.observation='UNKNOWN: interface, address or route collection unavailable. No empty-configuration inference permitted.'
        return $result
    }
    $addresses=@($Baseline.addresses.value | Where-Object {$_.AddressFamily -eq $Family})
    $default=if($Family -eq 'IPv4'){'0.0.0.0/0'}else{'::/0'}
    $routes=@($Baseline.routes.value | Where-Object {$_.AddressFamily -eq $Family -and $_.DestinationPrefix -eq $default -and $_.Store -eq 'ActiveStore'})
    $tunnels=@($Baseline.interfaces.value | Where-Object {$_.InterfaceDescription -eq 'Meta Tunnel' -and $_.Status -eq 'Up'})
    $tunnelIndexes=@($tunnels|ForEach-Object {$_.ifIndex})
    $tunnelRoutes=@($routes | Where-Object {$_.InterfaceIndex -in $tunnelIndexes})
    $result.observation="OBSERVED: $($addresses.Count) $Family addresses and $($routes.Count) active default routes in collector scope. Native and application reachability remain UNKNOWN."
    if($tunnelRoutes.Count){$result.hypothesis='An active Meta Tunnel default route may intercept tests; native bypass is unproven.'}
    if(-not $addresses.Count){$result.openQuestions+=@('No addresses observed in this sampling scope; upstream support is not determined.')}
    $result
}
function Get-NetworkDiagnostics {
    param([Parameter(Mandatory)][object]$Baseline,[Parameter(Mandatory)][hashtable]$Context)
    @((Get-NetworkFamilyDiagnostics -Baseline $Baseline -Context $Context -Family IPv4),(Get-NetworkFamilyDiagnostics -Baseline $Baseline -Context $Context -Family IPv6))
}
function New-NetworkValidation {
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][string[]]$EvidenceIds,[ValidateSet('IPv4','IPv6')][string]$Family='IPv4')
    $v=New-NetworkObject -Type ValidationResult -Context $Context -EvidenceIds $EvidenceIds
    $v.testId="native-$Family";$v.changeId=$null;$v.target=New-NetworkResource -Family $Family
    $v.startedAt=$null;$v.endedAt=$null;$v.conditions=@{path='native';family=$Family;pathProof='UNKNOWN'};$v.observations=$null
    $v.status='NOT_RUN';$v.failureReason='Native bypass was not proven. No native end-to-end test was selected; a same-host socket probe cannot prove native or proxy egress.';$v.blocking=$true;$v.evidenceLocations=@();$v.comparison=$null
    $v
}
function New-NetworkProposal {
    param([Parameter(Mandatory)][object]$Baseline,[Parameter(Mandatory)][object[]]$Diagnostics,[Parameter(Mandatory)][hashtable]$Context)
    $proposal=New-NetworkObject -Type ChangeProposal -Context $Context -EvidenceIds @($Baseline.evidenceIds)
    $proposal.baselineId=$Baseline.id;$proposal.diagnosticIds=@($Diagnostics | ForEach-Object {$_.id});$proposal.resource=New-NetworkResource
    $proposal.reason='现有证据不能支持安全修复。按下列诊断分别补齐观测，再决定是否提出单一配置变更。'
    $proposal.risk='high';$proposal.expectedOutcome='取得可追溯的地址族、路径和配置所有权证据；不改变网络。'
    $proposal.preconditions=@(@{id='runtime-ownership';resource=(New-NetworkResource -Kind flclash);operator='verified';expected=$true;evidenceFreshnessSeconds=60})
    $proposal.authorization=$null;$proposal.changeSetId=$null
    $steps=[Collections.Generic.List[object]]::new()
    foreach($diagnostic in $Diagnostics){
        $family=$diagnostic.family
        $missing=@(@('interfaces','addresses','routes') | Where-Object {$Baseline[$_].classification -eq 'UNKNOWN'})
        if($missing.Count){
            $action="只读重采 $family 的 $($missing -join ', ')，记录采集身份、时间、接口与 ActiveStore/PersistentStore；权限不足时保留 BLOCKED。"
            $expected='每项都有当前编号证据。成功空结果与访问失败可区分；失败不能推导为无地址或无路由。'
        }else{
            $action="选择待诊断目标，只读核验 $family 的目标路由、源接口和实际捕获路径；核对 TUN 与物理接口，不修改路由或代理模式。"
            $expected='目标路由、源接口和捕获证据相互一致。没有证实绕过 TUN 时，原生连通性保持 UNKNOWN，TCP/TLS 测试仍为 NOT_RUN。'
        }
        $steps.Add(@{id="context-$family";diagnosticId=$diagnostic.id;family=$family;evidenceIds=@($diagnostic.evidenceIds);action=$action;expectedObservation=$expected;status='NOT_RUN';networkChange=$false})
        $recordType=if($family -eq 'IPv4'){'A'}else{'AAAA'}
        $steps.Add(@{id="dns-$family";diagnosticId=$diagnostic.id;family=$family;evidenceIds=@($Baseline.dns.evidenceIds);action="确认诊断目标后，按 $recordType 记录分别比较系统解析与已发现 DNS；记录实际查询路径、结果和超时，不清缓存或更换 DNS。";expectedObservation='解析结果有来源与路径证据；合成地址候选单列。查询成功不证明 TCP、TLS 或代理出口成功。';status='NOT_RUN';networkChange=$false})
    }
    if($Baseline.flclash.classification -eq 'UNKNOWN'){
        $steps.Add(@{id='runtime-ownership';diagnosticId=$null;family='NA';evidenceIds=@($Baseline.flclash.evidenceIds);action='确认 Core 所有的 loopback 控制器后，经合法凭据只读取得版本与配置白名单，并核对配置所有者；不猜密钥或编辑数据库。';expectedObservation='认证、实例与配置来源均有独立证据。401/403 保留 BLOCKED，磁盘配置和进程存在不能替代运行时。';status='NOT_RUN';networkChange=$false})
    }
    $proposal.evidenceSteps=@($steps)
    $proposal.validationPlan=@($steps | ForEach-Object {
        $step=$_
        @{testId=$step.id;target=(New-NetworkResource -Family $step.family -Kind $(if($step.family -eq 'NA'){'flclash'}else{'route'}));path='read-only-evidence';family=$step.family;expected=@{observation=$step.expectedObservation;diagnosticId=$step.diagnosticId;evidenceIds=@($step.evidenceIds)};blocking=$true;timeoutSeconds=15;repetitions=1;allowedFailureReason=$null}
    })
    $proposal.recoveryPlan=@{recoverability='none';reason='本观察提案仅补齐证据，不包含执行许可；生产修复需独立 RepairPlan。'}
    $proposal.state='PLANNED';$proposal.executable=$false
    $proposal
}
function New-NetworkReport {
    param([Parameter(Mandatory)][object]$Baseline,[Parameter(Mandatory)][object[]]$Diagnostics,[Parameter(Mandatory)][object[]]$Validations,[Parameter(Mandatory)][object]$Proposal)
    $mode=if($Baseline.synthetic){'SYNTHETIC FIXTURE — not current host evidence'}else{'HOST OBSERVATION — not an atomic snapshot'}
    $lines=[Collections.Generic.List[string]]::new()
    $lines.Add('# FlClash Windows 网络诊断报告');$lines.Add('');$lines.Add("$mode`n")
    $lines.Add("Baseline: $($Baseline.id); hostRef: $($Baseline.hostRef); time: $($Baseline.createdAt)`n")
    $lines.Add('本观察流程未修改网络。生产 apply/rollback 需要独立 RepairPlan 和准确授权散列。观察快照不可用于恢复。没有证实故障根因。');$lines.Add('')
    foreach($d in $Diagnostics){$lines.Add("## $($d.family)");$lines.Add('');$lines.Add($d.observation);if($d.hypothesis){$lines.Add("HYPOTHESIS: $($d.hypothesis)")};$lines.Add("Evidence: $($d.evidenceIds -join ', ')");$lines.Add('')}
    $lines.Add('## 采集状态');$lines.Add('')
    foreach($key in @('environment','interfaces','addresses','routes','dns','proxies','ipInterfaces','nrpt','processes','listeners','dataDirectories','flclash')){$fact=$Baseline[$key];$lines.Add("- $key`: $($fact.classification). $($fact.unknownReason) Evidence: $($fact.evidenceIds -join ', ')")}
    $lines.Add('');$lines.Add('## 未完成测试');$lines.Add('')
    foreach($v in $Validations){$lines.Add("- $($v.testId): $($v.status). $($v.failureReason)")}
    $lines.Add('');$lines.Add('## 证据补齐提案');$lines.Add('')
    $lines.Add($Proposal.reason);$lines.Add('')
    $lines.Add("Proposal: $($Proposal.id); state: $($Proposal.state); executable: $($Proposal.executable). 所有权尚未证实，不执行网络变更。")
    foreach($step in $Proposal.evidenceSteps){
        $lines.Add('');$lines.Add("### $($step.id) [$($step.family)] — $($step.status)")
        $lines.Add('');$lines.Add($step.action);$lines.Add("验收观察：$($step.expectedObservation)")
        $lines.Add("Diagnostic: $($step.diagnosticId); Evidence: $($step.evidenceIds -join ', ')")
    }
    $lines.Add('');$lines.Add('DNS 查询成功不证明 TCP、TLS、原生 IPv6 或代理出口成功。TUN、指定 DNS、noproxy 与源地址绑定的路径必须独立核验。')
    $lines -join "`n"
}
Export-ModuleMember -Function *-Network*
