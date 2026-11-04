# 疑似木马、攻击与防火墙

默认执行本机 audit，保留时间窗口、采集身份、证据 ID、截断和不可访问项。不扫描远端、不反制攻击源、不清理日志。优先保护用户当前业务和调查现场。

## 从现象走向证据

| 现象 | 可以说明 | 还需核验 |
| --- | --- | --- |
| TCP established / UDP endpoint | 当前本地端点或 TCP 状态 | PID 实例、程序用途、远端服务、应用行为 |
| 0.0.0.0/:: 监听 | 可接受相应本地地址连接 | 入站规则、profile、端口、来源范围、上游 NAT/ACL |
| 未签名 / 非 Valid 签名 | 磁盘签名验证结果 | 来源、SHA-256、安装历史、内存与其他检测 |
| Defender 检测历史 | 曾记录某威胁检测 | 时间、ThreatID、ActionSuccess、当前状态 |
| 4625 数量增加 | 登录失败 | 来源/账户/服务与重复凭据，不能直接认定爆破 |
| 5152/5157 或防火墙 DROP | 策略丢弃 | 预期应用、方向、匹配规则与上下文 |
| 日志空或 audit BLOCKED | 当前覆盖不足或空样本 | 审计策略、日志启用、保留、权限和时间范围 |

运行 `process-check -OwnerProcessId <PID>`，保持进程 handle 并核对 start time，获取磁盘 image 的 SHA-256、签名与 signer。Windows 链验证可能联网。结果不证明内存无注入、内核无 rootkit、文件无恶意或路径仍对应启动时原文件。不要上传可疑文件或 IP 到公共服务，除非已获授权。

## 防火墙核对

audit 同时读取 ActiveStore 与 PersistentStore profiles，读取 enabled rules 和 application/port/address filters。批量 filter 的 InstanceID 只提供定位线索；目标规则必须用关联 cmdlet 验证，不能凭 DisplayName 猜关联。

```powershell
$rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name '<精确规则名>' -TracePolicyStore
$rule | Get-NetFirewallApplicationFilter
$rule | Get-NetFirewallPortFilter
$rule | Get-NetFirewallAddressFilter
$rule | Get-NetFirewallServiceFilter
Get-NetFirewallProfile -PolicyStore ActiveStore
Get-Service BFE,MpsSvc
```

关注有效防火墙关闭、默认入站 Allow、任意程序/任意来源 Allow、远程管理或控制器对外监听、LocalRuleMerge、域策略覆盖及意外出站 Block。端口开放的结论需要当前路径的实测；不因为监听就说“已暴露到公网”。

经证据和当前授权支持，可计划 FirewallProfile 开启保护/丢弃日志，或 FirewallBlock 阻断指定程序与一个确切远端 IP。后者不能覆盖所有 IPv6/IPv4 地址、域名轮转、其他进程或现有连接终止语义；另行验证新连接与业务。不要在未经分析时删除所有 allow 规则或恢复整个防火墙默认。

## 检测与处置分开

需要恶意软件扫描时，先查看 Windows Security 的检测、隔离和更新状态，使用已安装的 Defender/企业安全产品。扫描可能自动隔离文件，属于单独的处置动作；用户已明确授权该动作时继续，不把普通审计自动升级为隔离。

需要持久化检查时，定向核对计划任务、Run/RunOnce、服务、驱动及 WMI subscriptions；命令行和 task actions 可能含凭据，不写入普通网络报告。高可信入侵迹象需保留日志/内存/文件散列，并评估本机或带外的隔离；不通过当前远程出口盲目断开所有网络。

报告分清已观察事实、相关性、假设、检测产品结论与调查覆盖。不得承诺“没有木马”或仅凭网络记录确认攻击者身份。
