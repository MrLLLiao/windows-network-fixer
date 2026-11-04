# 故障排查路径

把时间、目标域名/IP、应用、预期路径和地址族写进证据。每次只修已确认的一项资源，复测原故障后再推进。下面命令为定向只读调查；接口和目标必须来自当前机器的真实观察。

## 没网或路由异常

```powershell
Get-NetAdapter -IncludeHidden
Get-NetIPConfiguration -Detailed
Get-NetIPInterface -AddressFamily IPv4
Get-NetIPInterface -AddressFamily IPv6
Get-NetRoute -PolicyStore ActiveStore
Get-NetRoute -PolicyStore PersistentStore
Find-NetRoute -RemoteIPAddress '<故障目标 IP>'
Get-NetNeighbor -InterfaceIndex <真实 index>
```

先查链路/无线关联、DHCP 地址、重复地址、网关邻居，再查最长前缀和 route+interface metric。ActiveStore 无默认路由仍可能存在 TUN 的两条 /1、特定前缀或其他 compartment。不要把 Metric 小简单等同于所有目标都会走该路由。

手工路由错误且确认 Windows 是所有者时使用 RouteMetric/Add/Remove。TUN/VPN 所有的 auto-route 由该软件 UI/支持接口修复。持久路由、DHCP/RA 缺失、NIC 驱动或上游故障不由临时 ActiveStore 修改掩盖。

## 多代理与瞬时断流

运行 watch，同时记录用户切换动作时间。瞬时变化用 watch-events 注册路由/接口/地址和代理注册表通知；通知可在两次慢速采样之间记录变化时间。对照 proxySettings/WinHTTP hash、路由、DNS、PID+start time、监听 owner。两个名字可属于一个客户端的 UI/core/helper，不能按进程数量直接判冲突。

常见顺序：客户端 A 写系统代理，B 覆盖；A TUN 与 B TUN 抢路由；核心重启后旧 ProxyEnable 仍开启但端口不再监听；UI 与服务使用不同配置；应用自行读取环境代理或 DoH。采样只显示观察窗口，无法证明未采到的瞬时变化不存在。

先由用户意图确定唯一系统代理/TUN 所有者，再通过各软件支持接口停止重复自动接管。不要强杀所有代理、改订阅/数据库或不断后台抢写。收敛后才能执行 UserProxy/DNS/metric 的精确计划。

## IPv4 正常、IPv6 失败，或相反

分别对比地址状态、DHCP/RA、默认/目标路由、DNS A/AAAA、TCP、TLS、目标服务监听族。IPv6 link-local/ULA 存在不证明公网可用；无全局地址也不证明运营商永久不支持 IPv6。AAAA 正常、ICMP 失败均不能决定 TCP 结果。

```powershell
Get-NetIPAddress -AddressFamily IPv6
Get-NetIPInterface -AddressFamily IPv6
Get-DnsClientServerAddress -AddressFamily IPv6
Get-DnsClientNrptPolicy -Effective
Resolve-DnsName '<故障域名>' -Type A -DnsOnly -QuickTimeout
Resolve-DnsName '<故障域名>' -Type AAAA -DnsOnly -QuickTimeout
```

用 path-probe 对同服务的两族真实 IP 分别测试，明确 SNI/TLS 名称。考虑 Happy Eyeballs 掩盖单族故障、Fake-IP、NAT64/DNS64、VPN split DNS、DoH 和 TUN 截获。代理入口族、核心到节点族和目标族分别取证。不要把关 IPv6 当默认方案。

## DNS、PAC、WinHTTP、门户认证

检查按族接口 DNS、NRPT、hosts hash、应用 DoH、VPN 名称空间和已发现的 DNS。修复 DnsServers 前确认网络需要静态还是自动；公共 DNS 可能破坏企业内网、门户或 IPv6-only 网络。

WinINET 当前用户、WinHTTP、PAC/WPAD、环境变量和应用内代理是独立来源。技能默认只保存存在性/散列；需要查端点时在当前交互中定向读取，避免把含密码或 token 的 URL 写报告。不要运行 `netsh winhttp reset proxy` 作为通用修复。

网络门户可能返回 HTTP 重定向，而 TCP/TLS 成功只说明传输/握手。通过该网络的合法门户完成用户认证；不要绕过认证或关闭 TLS 校验。

## 卡顿、MTU、Wi-Fi、驱动或性能

```powershell
Get-NetAdapterStatistics
Get-NetIPInterface | Select-Object InterfaceIndex,AddressFamily,NlMtuBytes,ConnectionState
netstat -s
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'
  StartTime=(Get-Date).AddHours(-2)
} -MaxEvents 100
```

丢包需结合重传、Wi-Fi 漫游、信号、接口错误、邻居和上游拥塞。MTU/MSS/PMTUD、ICMP 被过滤、睡眠唤醒、网卡节能和驱动都可能导致间歇性问题。不同大小的用户授权测试需要明确目的和目标；不全局改 MTU、关 offload 或重装驱动试运气。需要 pktmon/ETW/抓包时另建短时、定向采集，先确认没有正在进行的捕获会话并保护数据。

## 每次修复的完成条件

配置读回、有效策略、原应用/域名/地址族都要复测。确认另一个地址族、局域网与必要 VPN 未回归；持续 watch 复核是否被所有者重写。区分“配置已收敛”“传输通过”“原业务恢复”，不要只报告一个 PASS。
