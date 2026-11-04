# Changelog

## 1.0.1 — 2026-11-04

- 技能更名为 `windows-network-fixer`，安装器默认目录、备份前缀与 UI 调用名同步更新。
- 发布版本升至 1.0.1；保留旧 producer、Schema、生产状态根、全局互斥名和 RepairPlan 合同版本，避免破坏既有事务与可回滚计划。
- 增加公开仓库 README 与 MIT LICENSE。
- 重构 GitHub README：新增 teaser、Highlights、Mermaid 流程、能力表、快速开始、安全边界、验证、引用与 Star History。

## 1.0.0 — 2026-11-04

- 新增独立生产修复协调器：单资源计划、主机/SID/散列绑定、10 分钟过期、全局 mutex、ProgramData 受限 ACL、不可覆盖写前日志、前态比较、独立读回、冻结与条件回滚。
- 支持手工 ActiveStore 路由、接口 metric、分族 DNS、当前用户代理开关、开启防火墙/丢弃日志与精确程序/IP block；明确区分配置提交和业务恢复。
- 新增 audit/watch/process-check/path-probe，覆盖常见代理/VPN、路由/DNS 变化、TCP/UDP owner、防火墙有效策略、Defender/有限事件和显式 TCP/TLS。
- 保留旧 v0.1.0/v0.2.0 观察 Schema、离线事务模型、同主机 Socket 与隔离 Lab；生产合同独立，不把旧观察转换成恢复备份。
- 新增故障、安全和恢复操作手册。测试结果及实机覆盖以 compatibility.json 为准。

## 0.2.0 — 2026-11-04

- 管理员门禁改为失败关闭的令牌检测；公共入口与内部 Lab 入口同时要求 `S-1-5-32-544` 与 High/System Integrity，Medium 管理员或无法解析的非交互标准用户令牌均返回 `BLOCKED`，不再依赖 `IsInRole`。

- Lab restore 对两枚 owned 地址先完成只读预检，再复核缺席状态与身份后补写；后续失败仅条件撤销本次新增，补偿不确定时显式报告 MANUAL_RECOVERY_REQUIRED。新增零写入、写前漂移与补偿回归。

- 修复 Restore-LabSnapshot 从 scripts/lab 解析生产 Schema 的根目录：路径边界与 Schema 共用实际 Skill 根；新增有效已拥有快照穿过真实 Schema 的离线回归，并验证非法 Schema/hash 在地址访问前拒绝。

- 修复 NetAdapter.InterfaceGuid 为带花括号字符串时的 Lab snapshot Schema 失败：control、snapshot、生产基线、所有权与清理比较统一先解析 GUID，再使用 D 格式；保留严格 Schema。

- 修复 R_02 F1–F7：Lab 按 Socket status 验收、所有变异入口核对固定短语、watchdog 提前覆盖创建窗口、控制记录前清理异常落盘；journal 绑定恢复关键字段并拒绝矛盾终态；控制器认证绑定唯一已核对的 TCP 连接。新增离线回归保持生产写入阻断。

- 增加纯离线事务状态机、ChangeSet 审批绑定、before-state 与目标漂移检查、fencing 期限、外部中断决策和严格 `RollbackResult` 语义。
- 增加真实同主机 IPv4/IPv6 TCP nonce 验证；只保存 nonce SHA-256，bind 与 connect 阶段分离，未分配地址保留 `nativeError=10049` 和 `connectAttempted=false`。
- 增加一次性 Hyper-V Internal 实验室：管理员、确认开关与固定短语、`WhatIf` 预览、状态根、精确交换机/适配器身份、生产指纹、hash-bound 地址快照、损坏拒绝、Worker 中断恢复和精确清理；清理失败使用 `MANUAL_RECOVERY_REQUIRED`。
- journal 对完整规范化 ChangeSet 计算 SHA-256，并以前一事件 hash 链校验每次状态转换。
- 保留 0.1.0 观察快照、完整性和差异读取；仅只读观察合同接受旧 producer，新写对象使用 0.2.0。
- 生产 `apply`、`rollback` 和可恢复观察快照继续关闭。v0.2.0 管理员实机 Lab 必须通过安装后公共入口复测；此前 `attempt3` 是外部旧 harness 的历史证据，不能替代新代码复测。

## 0.1.0 release corrections

- Track the state module and verify the public CLI from a clean tracked export.
- Derive read-only evidence completion steps from each family diagnostic, retain UNKNOWN ownership and NOT_RUN status, and expose actions and acceptance observations in reports.

## 0.1.0 — 2026-11-03

- 首次发布只读 FlClash/Windows 调查、IPv4/IPv6 独立有限诊断与证据报告。
- 增加离线合成夹具、八种数据合同、不可执行的修复提案。
- 增加观察快照、完整性、历史与差异；快照不可恢复。
- 网络 apply/rollback、TCP/TLS 端到端验证、自动修复、事务恢复尚未提供。
