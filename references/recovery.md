# 生产事务、冻结与恢复

v1.0.1 的生产 RepairPlan 和数字事件日志独立于旧 v0.2.0 ChangeSet/TransactionJournal。不要把旧观察快照、LabAddressSnapshot 或离线 approval 传给生产执行器。

## 写入约束

生产根固定为 `%ProgramData%\CodexNetworkRepair`。根和每个事务目录设置受保护 DACL，仅 SYSTEM、Administrators、执行 SID 具有继承 FullControl。所有执行者使用同一 `Global\CodexWindowsNetworkRepair-v1` mutex；互斥量不可用即失败，不依靠删除锁文件抢锁。

应用顺序：

1. 验计划结构、哈希、主机、用户、有效期和请求白名单。
2. 获得实际提升令牌，通过 ShouldProcess；WhatIf 不创建生产状态。
3. 获得全局 mutex；检查其他事务是否已经收敛。
4. 独立读前态；创建唯一目录；以 CreateNew/Flush(true) 写 plan 和 PREPARED。
5. 再核计划与前态；先落盘 APPLYING，再调用一次精确系统写操作。
6. 独立读回并记 VALIDATING；防火墙还核 ActiveStore；250ms 后再次读回，匹配才记 COMMITTED。

COMMITTED、ROLLED_BACK、ABORTED 之外的事务冻结后续新 apply。ABORTED 是预留终态，当前没有自动写入路径。目录已存在时拒绝重放同一 apply。磁盘满、缺权限、短写或 JSON 损坏可能留下部分目录；此时冻结是预期行为，不能删目录绕过。

每个 `000000.json` 事件绑定 planHash、序号、前一事件散列和观测；读取拒绝缺号或不匹配的链。该链不抵御管理员有意重写或完整旧前缀替换，不是不可篡改审计。Plan 散列也不等于操作者授权。

后续同资源事务会阻止旧计划回滚，避免“撤销较新的修复”。ROLLED_BACK 是终态，不能再写回旧 desired。当前恢复路径只对一笔已观察事务做一次逆操作，不通过日志重演整个历史。

## 失败与有条件回滚

| 当前独立观察 | 行为 |
| --- | --- |
| 等于 before | 已恢复，无逆写；记录 ROLLED_BACK |
| 等于 desired | 记录 ROLLING_BACK；再读一次；执行准确逆操作并读回 before |
| 两者皆非或无法读取 | MANUAL_RECOVERY_REQUIRED；禁止覆盖 |

丢失回执也按实际当前值判断。失败可能来自实际操作、有效策略、日志落盘、通知或后续漂移；不要仅根据异常假设“没改成功”。

显式 rollback 可对已提交事务执行条件补偿；这与旧离线事务终态规则不同。回滚不要求旧 apply 计划仍未过期，但必须同主机、同 SID、准确计划散列和真实前态。进程文件删除不应妨碍撤销该计划的精确防火墙规则。当前值漂移时保留现场，不删除第三方规则。

## 中断处理

先 `repair-status`：读取日志并独立比较 current/before/desired，始终返回 `safeToReplay=false`。结果为 desired 只证明观察到配置，未完成的事务不能直接标记 COMMITTED。使用显式 rollback 收敛，再从新观察生成新计划。

读不出 plan、journal、资源或有效策略时，报告准确目录、计划 ID、资源 GUID/规则名、最后完整事件、当前权限与需人工补查项；保留 MANUAL_RECOVERY_REQUIRED。现场由管理员核验后恢复至可证实前态，再用现有 rollback 验收。没有可信前态时不能编辑 JSON 制造 ROLLED_BACK，也不提供“强制继续”。

防火墙开启计划的逆操作可能重新关闭该 profile；若威胁仍在，不应机械执行逆操作。保持保护并按人工恢复路径评估。远程会话或正在使用的出口可能受 route/DNS/metric 修复影响；执行前准备本地或带外路径。

## 旧功能

`recovery-check` 继续验证旧 TransactionJournal Schema、哈希链、ChangeSet approval 和 before/current/desired 决策；它不写网络，固定 `safeToReplay=false`、`automaticWriteAllowed=false`。观察 `SnapshotManifest` 永远 `recoverability=none`；旧 Lab 快照只属于其唯一拥有的隔离适配器。旧合同细节见 [contracts.md](contracts.md)。
