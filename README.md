# Windows Network Fixer

Windows 本机网络诊断与受控修复技能，面向 Codex 和其他支持 `SKILL.md` 的代理运行环境。重点覆盖路由表、接口 metric、DNS、IPv4/IPv6 分族验证、FlClash/Mihomo 与多代理瞬时竞态、防火墙状态和有限本机安全取证。

默认只读取证。生产修复必须先生成绑定当前主机、用户、前态、目标和有效期的单资源配置计划，再使用计划散列执行；支持独立读回、失败补偿和条件回滚。

## 要求

- Windows 10/11 或 Windows Server
- PowerShell 7.4 及以上
- 普通诊断无需管理员；生产修复需要实际提升的管理员令牌

不支持 Windows PowerShell 5.1。

## 安装

从源码目录运行安装器：

```powershell
pwsh -NoProfile -File .\scripts\install\Install-NetworkSkill.ps1 -WhatIf
pwsh -NoProfile -File .\scripts\install\Install-NetworkSkill.ps1
```

默认安装到 `%USERPROFILE%\.codex\skills\windows-network-fixer`，旧文件备份到 `%LOCALAPPDATA%\CodexSkillBackups`。安装器逐文件校验 SHA-256，不修改网络配置。

也可以把整个目录复制到宿主技能发现路径。入口为：

```text
scripts/entrypoints/Invoke-NetworkSkill.ps1
```

## 快速开始

```powershell
$entry = '.\scripts\entrypoints\Invoke-NetworkSkill.ps1'
$state = Join-Path $env:LOCALAPPDATA 'CodexNetworkState'

& $entry -Intent diagnose -StateRoot $state
& $entry -Intent audit -StateRoot $state
& $entry -Intent watch -StateRoot $state -Samples 10 -IntervalMilliseconds 500
& $entry -Intent watch-events -StateRoot $state -DurationSeconds 30
```

IPv4、IPv6 和 TLS 路径探测使用显式数字目标：

```powershell
& $entry -Intent path-probe -ProbeAddress '<IPv4-or-IPv6>' -ProbePort 443 -TlsName '<hostname>'
```

`path-probe` 不绕过 TLS 验证，不发送 HTTP 正文，也不证明流量绕过了 TUN。

## 修复流程

```powershell
$plan = & $entry -Intent repair-plan -RepairRequestPath '<request.json>' -StateRoot $state
$plan | Format-List

& $entry -Intent apply -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash -WhatIf
& $entry -Intent apply -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash

& $entry -Intent repair-status -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash
& $entry -Intent rollback -RepairPlanPath $plan.planPath -ApprovedPlanHash $plan.planHash
```

生产状态固定在 `%ProgramData%\CodexNetworkRepair`。一份计划只修改一项资源，缺计划、缺散列、主机/用户漂移、前态漂移或权限不足时失败关闭。

支持的计划类型：

- ActiveStore 路由 metric、单条路由添加/删除
- 接口 metric
- 按地址族的静态或自动 DNS
- 当前用户系统代理开关
- 防火墙 profile 开启与丢弃日志
- 指定程序或单个远端 IP 的精确阻断规则

TUN/VPN 自动路由、GPO/MDM、复杂防火墙策略、WinHTTP/PAC 和代理软件内部配置不由本技能直接接管。

## 安全边界

- 不相信“未发现”即可证明安全。监听端口、普通连接、未签名文件和历史检测需要结合上下文判断。
- `process-check` 检查指定 PID、磁盘文件散列和签名，不扫描进程内存，不证明未被注入。
- 不自动结束进程、删除文件、清理日志或扫描第三方主机。
- 不把关闭防火墙、禁用全部 IPv6、清空路由、重置 Winsock 或停止代理作为通用修复。
- 分享 audit/watch 报告前应脱敏，报告可能包含本机路径、IP 和网络拓扑。

详细操作手册位于 `references/`。

## 验证

```powershell
& .\tests\Invoke-Tests.ps1
& .\tests\Invoke-RepairTests.ps1
& .\tests\Invoke-LiveSmoke.ps1
& .\tests\Invoke-CleanReleaseTest.ps1
```

回归默认使用模拟 provider，不修改生产网络。实际覆盖和未测项目以 `manifests/compatibility.json` 为准。

## 许可证

[MIT](LICENSE)
