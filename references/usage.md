# 命令与输出

需要 PowerShell 7.4+；不支持 Windows PowerShell 5.1。普通诊断不要求管理员，受限采集逐项保留 BLOCKED；生产执行必须实际提升令牌。状态目录必须与技能分离。

```powershell
$skill = '<已安装技能的绝对目录>'
$entry = Join-Path $skill 'scripts/entrypoints/Invoke-NetworkSkill.ps1'
$state = Join-Path $env:LOCALAPPDATA 'CodexNetworkState'

$baseline = & $entry -Intent diagnose -StateRoot $state
$audit = & $entry -Intent audit -StateRoot $state
$audit.report

# 采样间隔还包含采集耗时；本命令不保证捕获毫秒级竞态。
& $entry -Intent watch -StateRoot $state -Samples 10 -IntervalMilliseconds 500
& $entry -Intent watch-events -StateRoot $state -DurationSeconds 30

# 显式发出 DNS 查询，不证明实际出口。
& $entry -Intent diagnose -StateRoot $state -ProbeDns -DnsName example.com

# 显式连接指定目标；地址与 TLS 名称须由当前故障目标提供。
& $entry -Intent path-probe -ProbeAddress '<目标 IPv4>' -ProbePort 443 -TlsName '<目标域名>'
& $entry -Intent path-probe -ProbeAddress '<目标 IPv6>' -ProbePort 443 -SourceAddress '<本机 IPv6>' -TlsName '<目标域名>'

# 仅检查自己要调查的进程。签名及磁盘散列不能证明内存未被注入。
& $entry -Intent process-check -OwnerProcessId <PID>
```

`path-probe` 不使用 HTTP 代理、不发送 HTTP 正文、不绕过 TLS 验证，也不声称绕过 TUN。TLS 证书链可能联网检查撤销状态。连接和 TLS 共用 1–30 秒取消预算；系统调用与路由采集仍可能增加实际耗时。

`audit` 包含默认 compartment 的接口/路由/DNS、常见代理进程、TCP/UDP、TCP owner、WinHTTP binary hash、防火墙 profiles/rules/filters、Defender 状态/检测历史、近两小时的有限事件与 hosts 文件散列。最多 4096 TCP、4096 UDP、256 owner、2048 enabled rules、各 4096 filters。截断标志保留；事件正文、命令行、PAC URL 与代理明文不保存。Defender 未安装、日志未启用或拒绝访问均保留限制，不代表无威胁。

`watch` 保存 `sample-NNN.json`、`changes.json` 和报告。配置数组先规范化排序，再比较散列，避免仅因枚举顺序变化误报。采集非原子；记录变化不等于确定写入者。

`watch-events` 注册原生路由、IP 接口、单播地址变化和当前用户 Internet Settings 注册表通知，覆盖 IPv4/IPv6。它在后台回调中保存 UTC 与单调时钟时间戳，100ms 批次落盘；每次回调入队上限 2048，`dropped` 记录丢失。每项 coverage=0 表示注册成功，非零为具体 Win32 错误或代理注册异常。状态 PASS 仅表示监听成功，不表示窗口内没有漏通知或网络健康；注册表通知可能合并，任何键值变化也可能与代理无关。通知不提供写入 PID、变更前值或完整路由行。结合 watch 的状态快照与用户操作时间判断，不宣称已归因。

事件 summary 的 cleanup 记录取消通知返回码。非零表示未确认全部释放，保持 PARTIAL；剩余委托会保留到进程结束以避免悬空回调。不要在长期宿主中不断重试。

## 验证与安装

```powershell
& (Join-Path $skill 'tests/Invoke-Tests.ps1')
& (Join-Path $skill 'tests/Invoke-RepairTests.ps1')
& (Join-Path $skill 'tests/Invoke-LiveSmoke.ps1')
& (Join-Path $skill 'tests/Invoke-CleanReleaseTest.ps1')
```

回归用模拟 provider，不改生产配置。LiveSmoke 仅使用临时文件、同机 TCP/TLS 端点和只读通知；不把 self-signed 证书加入信任库。CleanRelease 默认从白名单文件导出独立包；可用 `-Revision <git ref>` 验证已提交的精确版本。

从独立源码目录运行 `scripts/install/Install-NetworkSkill.ps1`，先 `-WhatIf`。默认备份旧安装到 `%LOCALAPPDATA%\CodexSkillBackups`，随后复制白名单文件并逐文件核验 SHA-256。保留安装目录中非包文件，不删除历史观察；备份不放在技能发现目录中。安装本身不修改网络。

## 修复

请求格式和操作白名单见 [repair.md](repair.md)。一份计划只对应一个资源。

```powershell
$plan = & $entry -Intent repair-plan -RepairRequestPath '<request.json>' -StateRoot $state
$plan | Format-List

& $entry -Intent apply -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash -WhatIf
& $entry -Intent apply -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash

& $entry -Intent repair-status -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash
& $entry -Intent rollback -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash -WhatIf
& $entry -Intent rollback -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash
```

计划默认 10 分钟失效。哈希绑定主机 MachineGuid、当前用户 SID、请求、前态、目标与程序文件散列；不是身份认证。执行者必须已经有当前任务的变更授权。生产事务固定保存到 `%ProgramData%\CodexNetworkRepair\repair-UUID`，不受观察用 `-StateRoot` 影响。

`apply` 缺计划、缺准确散列或 `-Fixture` 时返回 BLOCKED。其他输入/权限错误为终止错误。`-WhatIf` 不创建生产事务或写网络，但会读取计划和前置条件。中断禁止重放同一 apply；先检查真实状态。

## 传统观察与控制器

```powershell
& $entry -Fixture -StateRoot $state
& $entry -Intent history -StateRoot $state
& $entry -Intent integrity -StateRoot $state -RunId $baseline.runId
$next = & $entry -Intent snapshot -StateRoot $state
& $entry -Intent diff -StateRoot $state -RunId $baseline.runId -OtherRunId $next.runId
```

传统观察仍使用 v0.2.0 producer/schema，兼容 v0.1.0；技能版本为 v1.1.0。观察快照不可恢复。audit/watch/repair-plan 不是传统观察快照，不能传给旧 integrity/diff。audit-manifest 仅记录文件散列，没有签名。

只读 FlClash 控制器要求明确数字 loopback 根 URI 和准确进程所有权；非默认安装还需准确可执行文件路径。不自动探测端口或密钥。

```powershell
$secret = Read-Host '控制器认证' -AsSecureString
& $entry -Intent diagnose -StateRoot $state `
  -ControllerUri 'http://127.0.0.1:<已核验端口>/' `
  -CoreExecutablePath 'D:\Verified\FlClash\FlClashCore.exe' -ApiSecret $secret
Remove-Variable secret
```

同主机 nonce echo 使用原 `socket-probe -ProbeAddress ... -ProbePort ... -ProbeNonce ...`。独立 Lab 使用原门禁：

```powershell
$labState = Join-Path $env:LOCALAPPDATA 'CodexNetworkLabState'
& $entry -Intent lab -StateRoot $labState -ConfirmLabMutation `
  -LabConfirmation CREATE_AND_REMOVE_ISOLATED_HYPERV_LAB_NETWORK
```

运行前读 [lab.md](lab.md)。`recovery-check` 保留旧离线 TransactionJournal 决策，不执行新生产事务恢复。
