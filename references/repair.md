# 精确修复计划

请求 JSON 只允许 `kind`、`target`、`desired`。拒绝额外字段和任意命令；执行器不调用 Invoke-Expression、shell 字符串、用户提供的脚本或下载代码。

所有接口操作必须用 `Get-NetAdapter -IncludeHidden` 返回的真实 InterfaceGuid，不能仅依赖可能复用的名称或 index。`family` 只允许 `IPv4`/`IPv6`。执行前重新用 GUID 解析当前 index。

| kind | target | desired | 恢复单位 |
| --- | --- | --- | --- |
| RouteMetric | interfaceGuid, family, destinationPrefix, nextHop | routeMetric: 1–65535 | 精确路由的原 metric |
| RouteAdd | 同上 | routeMetric | 仅删除本计划新增且仍匹配的路由 |
| RouteRemove | 同上 | 空对象 `{}` | 仅在该路由仍缺席时补回前态 |
| InterfaceMetric | interfaceGuid, family | automaticMetric: Enabled/Disabled, interfaceMetric: 1–9999 | 原自动开关与手动 metric |
| DnsServers | interfaceGuid, family | automatic: bool, servers: numeric IP array | 该族原静态列表或自动来源 |
| UserProxy | scope: CurrentUser | enabled: bool | 原 ProxyEnable 是否存在及值 |
| FirewallProfile | profile: Domain/Private/Public | enabled: true, logBlocked: true | 本地 PersistentStore 前态 |
| FirewallBlock | program: absolute file path, direction: Inbound/Outbound, remoteAddress: one IP | blocked: true | 仅删除本计划唯一规则 |
| FirewallBlockAddress | direction: Inbound/Outbound, remoteAddress: one IP | blocked: true | 仅删除本计划唯一远端 IP 规则 |

路由必须是 ActiveStore 中未发布、无限生存期、Protocol=NetMgmt 的手工路由，且不存在同键 PersistentStore 路由。拒绝 DHCP/RA 自动路由、多 compartment 歧义或持久路由。不能用加默认路由替代“查出真实网关”。已发现的上游、接口和网关关系必须另有证据。

接口 metric 仅修改 ActiveStore；自动 metric 的数值随系统变化，验证自动模式时不强求原数值。DNS 用按族 `Get-DnsClientServerAddress` 的唯一 CIM 对象传给 Set，避免同时重写两族。静态/自动来源从该接口 Tcpip/Tcpip6 `NameServer` 读取；无法读取则拒绝。自动恢复不保证 DHCP/RA 随后提供同样服务器。

UserProxy 只改当前身份的 ProxyEnable，不改 ProxyServer/PAC/WinHTTP/环境变量；存在相关策略分支则转策略所有者。前态还绑定 ProxyServer/PAC/AutoDetect 散列，防止变化后继续。通知 WinINET 刷新不保证每个应用立即采用新值。

FirewallProfile 只提供开启保护和丢弃日志；验证 ActiveStore 的有效结果。计划记录本地前态，因此条件回滚可能恢复此前关闭的防火墙状态；需要确认仍符合原修复授权和当前安全目标。FirewallBlock 必须指定一个真实程序文件和一个准确远端 IP。FirewallBlockAddress 可阻断一个明确的攻击源/目的 IP；两者均不接受 Any、CIDR、loopback 或全机断网。

全局唯一规则名由计划生成；比较程序、方向、地址、动作、启用、profile、description、端口、服务和接口过滤后才允许删除。活动防火墙关闭或有效规则缺失时，验证失败而非谎报已阻断。GPO/MDM 可使本地规则无效。

## 示例：修正已有路由 metric

```json
{
  "kind": "RouteMetric",
  "target": {
    "interfaceGuid": "11111111-1111-1111-1111-111111111111",
    "family": "IPv4",
    "destinationPrefix": "0.0.0.0/0",
    "nextHop": "192.0.2.1"
  },
  "desired": {"routeMetric": 50}
}
```

GUID 和 TEST-NET 网关仅示例，必须替换为该主机已核验资源。不要把示例发送到生产执行器。

## 示例：该接口 IPv6 恢复自动 DNS

```json
{
  "kind": "DnsServers",
  "target": {
    "interfaceGuid": "11111111-1111-1111-1111-111111111111",
    "family": "IPv6"
  },
  "desired": {"automatic": true, "servers": []}
}
```

静态 DNS 要求 `automatic=false`，服务器全部为同族数值 IP，最多 8 个。不要随意改成公共 DNS；先核对 VPN、NRPT、企业分流和 DoH 所有者。

## 执行与验收

计划生成、预览、apply/status/rollback 命令见 [usage.md](usage.md)。只有当前配置等于计划前态时才应用。一次系统调用并非原子事务；适配器或第三方可在最后检查后变化。读回异常时不覆盖陌生状态。

`COMMITTED` 不等于上网恢复、代理出口正确、恶意连接已彻底阻断或没有其他程序重写。随后按原目标运行 DNS/TCP/TLS 和一轮 watch，检查原故障与其他地址族均未回归。
