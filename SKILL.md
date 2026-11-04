---
name: windows-network-fixer
description: 诊断和修复 Windows 本机网络、FlClash/Mihomo 及多代理冲突；覆盖路由、DNS、IPv4/IPv6 分族验证、波动采样、防火墙与疑似入侵取证。执行可审阅计划、精确资源变更和条件回滚。
metadata:
  version: "1.1.0"
---

# Windows 网络诊断与修复

Windows、PowerShell 7.4+。默认只读取证；用户要求修复时，根据证据生成可执行计划并在已有授权范围内继续。开发本技能的授权不等于修改开发机网络的授权。不要把 v0.2.0 的生产写入关闭规则继续套到 v1.1.0。

入口：`scripts/entrypoints/Invoke-NetworkSkill.ps1`。以技能的实际绝对目录定位。无需安装模块、连接器、服务或浏览器插件。日常命令与输出见 [usage.md](references/usage.md)。

## 工作流程

1. 明确故障目标、发生时间、是否经代理以及影响地址族。优先读取已有证据；用 `diagnose` 采集传统基线，`audit` 补齐多代理、TCP/UDP、进程、防火墙与安全日志。
2. 间歇断网、代理切换、DNS/路由反复变更时运行 `watch`；瞬时变化再用 `watch-events` 注册原生通知。保存采样与事件时间线，进程共存不是竞态定论。定位路径见 [playbooks.md](references/playbooks.md)。
3. IPv4、IPv6 独立验证：`-ProbeDns` 分开 A/AAAA；`path-probe` 使用明确目标 IP，选定源地址后测试 TCP，可用 `-TlsName` 验证 TLS。TUN/WFP 截获仍可能存在，成功不能自动升级为原生出口证明。
4. 需要修复时，读 [repair.md](references/repair.md)，生成一项精确资源的 `repair-plan`，核对 before/desired 与计划散列。已有修复授权足够时继续 `apply`，不要反复索取相同授权。缺权限保持可审阅结果，按宿主权限机制处理，不能把高权限口头声明当成已提升的令牌。
5. 变更后重新跑受影响地址族及原故障场景。`COMMITTED` 只代表配置读回和短时稳定检查通过。失败自动尝试有条件补偿；中断先 `repair-status`，需要时 `rollback`。恢复与冻结规则见 [recovery.md](references/recovery.md)。

## 能力与边界

可执行修复：手工 ActiveStore 路由添加/删除/metric、接口 metric、按地址族设置或恢复自动 DNS、当前用户系统代理开关、开启防火墙及丢弃日志、添加指定程序或单个远端 IP 的精确阻断规则。每份计划只修改一项资源，路由不改 PersistentStore。

DHCP/RA、VPN/TUN 自动路由、GPO/MDM、防火墙复杂策略、WinHTTP/PAC 和代理软件内部设置，由相应所有者处理。技能提供检查命令和决策路径；没有可验证逆操作时不伪造自动修复。不要通过直接改 FlClash 数据库或订阅文件抢夺控制权。不要把关闭防火墙、全局禁用 IPv6、删除全部路由、重置 Winsock、停掉所有代理当作通用修复。

疑似木马、被攻击或防火墙暴露时，读 [security.md](references/security.md)。`audit` 保存有限本机证据；`process-check` 检查指定 PID 的实例、磁盘文件散列和签名。签名检查可能触发 Windows 的证书链网络验证。普通连接、未签名文件、监听端口、历史检测和丢包记录不能单独证明攻击；“未发现”也不能证明安全。不扫描第三方主机，不自动结束进程、删除文件或清理日志。

生产状态固定在 `%ProgramData%\CodexNetworkRepair`，受限 ACL、全局互斥、写前事件链、前态比较、独立读回与条件回滚共同约束执行。散列用于一致性和意外损坏检查，不是签名、操作者认证或抵御管理员篡改的安全边界。Windows cmdlet 没有跨进程原子 CAS；多代理持续争抢时应先通过所有者接口收敛，再修复。

旧 `snapshot/integrity/history/diff` 继续处理观察记录，`recoverability=none`。新 audit/watch 的文件格式独立，不适用旧观察 integrity；勿混用。旧离线事务和 Hyper-V Lab 仍兼容，Lab 门禁见 [lab.md](references/lab.md)。证据和 UNKNOWN 语义见 [contracts.md](references/contracts.md)，诊断限制见 [diagnostics.md](references/diagnostics.md)。

当前兼容性、实测与未测项目见 [compatibility.json](manifests/compatibility.json)。官方依据见 [sources.md](references/sources.md)。运行数据置于技能和源码仓库之外；报告可能含本机路径、IP 与拓扑，分享前另做脱敏副本。
