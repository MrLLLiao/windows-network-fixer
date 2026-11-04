# 官方依据

核验日期：2026-11-04。资料事实不代表 v1.0.1 已在目标主机完成相应操作。

- [FlClash 官方说明](https://github.com/chen08209/FlClash/blob/main/README.md)：客户端使用 Mihomo，支持系统代理与 TUN。
- [FlClash v0.9.1 路径源码](https://github.com/chen08209/FlClash/blob/v0.9.1/lib/common/path.dart)：应用支持目录的来源；目录存在仍只作为候选。
- [Mihomo API](https://github.com/metacubex/meta-docs/blob/main/docs/api/index.en.md)：`GET /version` 与 `/configs` 是有限只读入口。
- [Mihomo TUN](https://github.com/metacubex/meta-docs/blob/main/docs/config/inbound/tun.en.md)：自动路由与 DNS 会影响路径，原生出口需独立证明。
- [Microsoft Get-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute)：需要区分地址族、PolicyStore 与 compartment。
- [Microsoft Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress)：可读取接口、地址、前缀与 PolicyStore。
- [Microsoft New-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netipaddress)：支持指定接口、前缀、`SkipAsSource` 与 `ActiveStore`。
- [Microsoft Remove-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/remove-netipaddress)：删除时仍需独立验证精确资源身份。
- [Microsoft New-VMSwitch](https://learn.microsoft.com/en-us/powershell/module/hyper-v/new-vmswitch)：创建虚拟交换机时显式选择 `Internal`。
- [Microsoft Get-VMSwitch](https://learn.microsoft.com/en-us/powershell/module/hyper-v/get-vmswitch)：用返回的准确 ID 与类型核验身份。
- [.NET TCP Socket](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/sockets/tcp-classes)：显式 `Socket.Bind`、`ConnectAsync` 与 listener 生命周期。
- [.NET SocketsHttpHandler](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/http/httpclient-migrate-from-httpwebrequest)：可在建立 HTTP 连接前显式绑定本地地址。
- [Microsoft Resolve-DnsName](https://learn.microsoft.com/en-us/powershell/module/dnsclient/resolve-dnsname)：可分别查询 A/AAAA，但不证明 TCP/TLS 可达。
- [Microsoft Test-Json](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/test-json)：`SchemaFile` 以 JSON Schema 验证输入。
- [Microsoft Set-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/set-dnsclientserveraddress)：按接口/族设置静态 DNS；`ResetServerAddresses` 恢复 DHCP 提供值。
- [Microsoft New-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netroute)：指定接口和 PolicyStore 创建路由。
- [Microsoft Set-NetIPInterface](https://learn.microsoft.com/en-us/powershell/module/nettcpip/set-netipinterface)：自动/手动接口 metric 与地址族属性。
- [Microsoft New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)：程序、方向、远端地址、动作与 profile 过滤。
- [Microsoft Set-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile)：profile 启用状态和日志策略。
- [Microsoft Get-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule)：有效/持久 PolicyStore 与关联过滤器。
- [Microsoft Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection)：本地/远端端点、状态与 owner PID。
- [Microsoft Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)：按日志/ID/起始时间有界读取事件。
- [Microsoft Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)：磁盘文件签名验证，不是运行时完整性证明。
- [Microsoft WinINET InternetSetOption](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptionw)：代理设置变化通知。
- [Microsoft NotifyRouteChange2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2)：原生路由变化回调，AF_UNSPEC 覆盖两族。
- [Microsoft NotifyIpInterfaceChange](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange)：IP 接口变化通知。
- [Microsoft RegNotifyChangeKeyValue](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue)：只读注册表变化订阅与 thread-agnostic 标志。
- [Microsoft CancelMibChangeNotify2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-cancelmibchangenotify2)：取消 IP helper 通知，不能在同一通知回调中取消以免死锁。
- [PowerShell TestJsonCommand source](https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.Commands.Utility/commands/utility/TestJsonCommand.cs)：GitHub 连接器用于核验 7.4 后严格 JSON 与 JsonSchema.NET 行为。

v1.0.0 开发时已尝试用户指定的 Context7/GitHub；当前 Context7 传输失败，GitHub 仅暴露账户查询。新增操作参数改用微软官方页面、本机 cmdlet 元数据及 FlClash 官方 README 核验。Skill 日常运行不依赖连接器，不下载代码；显式 DNS/连接/TLS/签名测试可能访问网络。
