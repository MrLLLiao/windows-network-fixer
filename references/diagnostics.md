# 诊断边界

L1/L2 采集网卡、地址和接口设置；L3 按 IPv4/IPv6 汇总 ActiveStore 与 PersistentStore 路由；L4 收集 DNS/NRPT，显式允许后查询 A/AAAA；L6 收集 FlClash 进程、监听、候选目录和可选只读 API。L5 的同主机 Socket 测试是独立显式意图；L7 应用与 L8 门户认证仍不自动判断。

默认路由不是每个目标的实际出口。必须考虑最长前缀、接口 metric、compartment、PolicyStore、TUN 和应用绑定。Meta Tunnel 活动默认路由只会产生“原生路径可能被截获”的假设。TUN、noproxy、指定 DNS、绑定源地址或同主机 Socket 成功都不能单独证明原生公网出口。

IPv4 与 IPv6 独立。网卡 Up、APIPA、link-local、ULA 或历史虚拟适配器存在都不构成全机故障结论。没有全局 IPv6 地址不能证明上游永久不提供 IPv6；RA/DHCPv6、路由、DNS、TCP/TLS 与真实出口需要分别取证。

WinINET 只覆盖采集身份 HKCU，PAC/ProxyServer 默认只记录存在性。WinHTTP、WPAD、应用代理与应用 DoH 仍是独立层。FlClash 候选目录存在不证明当前进程使用它；磁盘配置不构成运行时事实。

管理 API 只允许数字 loopback、根路径、无 userinfo/query/fragment。监听必须属于当前 PID，且 process executable 必须是 `FlClashCore.exe`。默认安装根为 `%ProgramFiles%\FlClash`；其他安装要求用户提供精确路径。路径比较排除同名 sibling 目录，但不声称签名验证。无所有权证据时不扫端口、不猜 Secret。

同主机 Socket 结果字段区分：

- `bindSucceeded`；
- `connectAttempted`；
- `nonceSha256`；
- `nonceMatched`；
- `clientClosed`；
- `failedStage`；
- `socketError` 与 `nativeError`。

结果只保存 nonce 的 SHA-256，不保存原文。本模块只拥有 client socket，因此 `clientClosed` 必须独立记录；外部 listener 的关闭状态不能用 client 结果推断，`listenerClosed` 保持 null。绑定未分配源地址时 `connectAttempted=false`。连接失败、nonce 不一致与 bind 失败不能合并。成功只证明该地址上的本机 listener/nonce 往返，不证明外部目标或出口。

根因必须先有编号证据和针对性测试。读取被拒、测试未跑和上游未知分别保留 `BLOCKED`、`NOT_RUN`、`UNKNOWN`；不得用空数组、UI 状态或退出码推断。
