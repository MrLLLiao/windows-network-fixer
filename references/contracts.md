# 数据、事务与存储契约

`schemas/` 包含十种 JSON Schema 2020-12 合同：

- 只读观察：`EvidenceRecord`、`NetworkBaseline`、`DiagnosticResult`、`ChangeProposal`、`SnapshotManifest`、`ValidationResult`。
- 写入事务：`ChangeSet`、`TransactionJournal`、`RollbackResult`。
- 隔离实验：`LabAddressSnapshot`。

`schemaVersion` 表示合同结构版本，与 Skill 发布版本分开。这里的旧合同仍为 `1.0.0`，对应对象写 producer `flclash-windows-network/0.2.0`。只读观察合同接受 producer `0.1.0` 与 `0.2.0`，因此已审查的 0.1.0 观察快照仍可用于 `integrity` 与同主机 `diff`。`ChangeSet`、`TransactionJournal`、`RollbackResult` 只接受 0.2.0 离线事务语义。v1.0.0 新增的生产 RepairPlan、audit 和 watch 独立使用运行时验证，不混入这些旧 Schema；旧观察对象不会变成可恢复快照。

Fact 使用 `OBSERVED / DOCUMENTED / PROPOSED / UNKNOWN`。`UNKNOWN.value` 必须为 null，且需要非空原因；`OBSERVED` 必须有证据。采集成功但没有条目是 `PASS + []`；采集失败是 `BLOCKED + null + 安全错误码`。测试状态 `PASS / FAIL / SKIP / BLOCKED / NOT_RUN` 与知识状态独立。

## 路径门禁

状态路径先经过语法检查，之后才允许 `GetFullPath`、`Test-Path` 或建目录。拒绝 UNC、`\\?\`、`\\?\UNC`、`\\.\`、NT/device namespace、drive-relative、DOS 设备名、ADS、通配符、父级 `..`、已有 reparse point，以及状态根与 Skill/Git 重叠。报告里的散列通过只证明字节一致，不证明来源、授权或恢复可行性。

观察快照仅保存脱敏投影，固定 `recoverability=none`、`observationOnly=true`。`manifestHash` 对自身字段置空后的紧凑 JSON 计算，条目只接受固定文件名和 UUID 格式。摘要引用不授权打开任意路径。

## ChangeSet 与审批

`ChangeSet` 描述一个逻辑单元和有序操作。`New-NetworkTransactionJournal` 从 ChangeSet 提取排序后的 target stable ID，并绑定：

- ChangeSet ID、hostRef；
- 所有操作资源 owner 与稳定身份；
- `expectedBeforeHash` 与 `desiredAfter` 的 SHA-256；
- 随机 fencing token 及期限。

`Approve-NetworkTransactionJournal` 再把授权 scope、principal、批准/过期时间和 binding hash 写入 journal。journal 保存完整规范化 ChangeSet 的 SHA-256，binding hash 再覆盖该 ChangeSet hash、target stable ID、before-state hash、desired-after hash、完整 fencing token/issuedAt/expiresAt、owner、principal、scope、批准时间与 expiry。重新提供 ChangeSet 时，任何字段变化，包括 operations 参数、顺序、逆操作或人工恢复步骤，都会使完整 ChangeSet hash 不匹配并拒绝。该绑定是状态绑定，不是用户身份认证或数字签名。

## Journal 状态机

允许的主链：

```text
PLANNED -> APPROVED -> APPLYING -> VALIDATING -> COMMITTED
```

允许的失败与恢复链：

```text
APPLYING -> ROLLING_BACK | MANUAL_RECOVERY_REQUIRED
VALIDATING -> FAILED_VALIDATION | MANUAL_RECOVERY_REQUIRED
FAILED_VALIDATION -> ROLLING_BACK | MANUAL_RECOVERY_REQUIRED
ROLLING_BACK -> ROLLED_BACK | ROLLBACK_FAILED | MANUAL_RECOVERY_REQUIRED
```

每次状态转换记录连续序号、时间、前一状态隐含历史、前一事件 hash、当前事件 hash 和规范化 journal decision data hash。decision data 覆盖 desired hash、fencing、validation IDs、未恢复资源 IDs、failureReason，以及主机、ChangeSet、owner、目标和 before hash；最后一项的 decision data hash 必须与顶层字段相同。事件 hash 对规范化 transition 内容计算；重算或前一事件链接不匹配即拒绝。时间倒退、序号回退、截断历史或最终状态与 `updatedAt` 不一致同样拒绝。过期 approval 或 fencing lease 不能启动 `APPLYING`。终态不可复用。`COMMITTED` 需要至少一个 ValidationResult ID，且未恢复资源必须为空。`ROLLED_BACK` 还需要验证 ID 且 `unrestoredResourceIds` 为零；`ROLLBACK_FAILED` 必须保留至少一个未恢复资源。拒绝状态转换不得修改原 journal 对象。

## 恢复语义

`Get-NetworkRecoveryDecision` 只读取 journal 与独立提供的 current-state SHA-256，绝不调用写入器。before/current/desired 三方比较会区分未执行、已执行待验证、部分执行、第三方漂移和完成状态。所有分支输出 `safeToReplay=false` 与 `automaticWriteAllowed=false`；进程退出码、旧回执或散列一致都不能替代独立状态读取。

`RollbackResult` 的 `ROLLED_BACK` 需要有独立验证，且不能隐藏未恢复资源。`ROLLBACK_FAILED` 必须列出未恢复资源；`MANUAL_RECOVERY_REQUIRED` 必须包含非空白的人工步骤。无法证明的状态保留 `MANUAL_RECOVERY_REQUIRED`。这些是旧离线合同；v1.1.0 的生产 apply/rollback 使用独立的 RepairPlan 与磁盘事件日志，详见 [recovery.md](recovery.md)。

## 隔离 Lab 快照

`LabAddressSnapshot` 只允许一次运行的两枚固定地址：

- `192.0.2.241/32`
- `fd42:6364:786c::241/128`

两者都必须 `SkipAsSource=true`、`PolicyStore=ActiveStore`，并绑定本次运行的 switch ID 与 adapter GUID。恢复先验证文件字节 SHA-256，再验证 Schema、identity、地址白名单和当前 ownership。任一失败都在地址写入前返回。该快照不是 Skill 观察快照，也不能用于生产恢复。
