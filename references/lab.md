# 一次性 Hyper-V Internal 实验室

本页是旧隔离 Lab 的操作合同。它只用于验证地址增删、Socket 门禁、hash-bound 快照和中断恢复，不修复生产网络。v1.1.0 的生产修复使用独立 RepairPlan，见 [repair.md](repair.md)。

## 固定范围

每次运行只允许：

- 创建一个唯一 `CodexLab-<12 lowercase hex>` 的 Hyper-V `Internal` 交换机。
- 管理该交换机自动生成的唯一 management adapter。
- 在该 adapter 的 `ActiveStore` 上创建两枚 `SkipAsSource=true` 地址：
  - `192.0.2.241/32`
  - `fd42:6364:786c::241/128`
- 在删除或恢复地址后执行同主机 nonce echo。

禁止接物理上行，禁止 NAT、默认网关、生产 DNS、生产路由、WinINET、WinHTTP、TUN、FlClash 配置或服务写入。任何同名交换机、已存在测试地址、额外 VM attachment 或 identity drift 都使运行失败。

## 启动门禁

执行前必须同时满足：

1. Windows 与 PowerShell 7.4+。
2. 管理员身份。
3. Hyper-V cmdlet 可用。
4. `StateRoot`/run directory 与 Skill、Git、reparse point 分离。
5. 公共入口收到 `-ConfirmLabMutation` 与字面值
   `-LabConfirmation CREATE_AND_REMOVE_ISOLATED_HYPERV_LAB_NETWORK`。
6. 引擎收到内部第二门 `-AllowMutation`。

任一失败在创建 run directory 或交换机前停止。引擎及 Interrupt/Watch 子进程同样核对固定短语；`-AllowMutation` 由入口加入，但单独提供此 switch 不构成授权。固定短语表示明确意图，不是身份认证或保密令牌。

管理员判断采用失败关闭语义：令牌必须同时包含 `S-1-5-32-544` 与 High/System Integrity（`S-1-16-12288` 或 `S-1-16-16384`）。只要无法可靠解析，或只是 Medium Integrity 管理员，就返回 `BLOCKED`，不会继续创建状态目录、交换机或地址。

```powershell
$skill = '<技能绝对目录>'
$entry = Join-Path $skill 'scripts/entrypoints/Invoke-NetworkSkill.ps1'
$state = Join-Path $env:LOCALAPPDATA 'CodexNetworkLabState'
& $entry -Intent lab -StateRoot $state `
  -ConfirmLabMutation `
  -LabConfirmation CREATE_AND_REMOVE_ISOLATED_HYPERV_LAB_NETWORK `
  -WhatIf

& $entry -Intent lab -StateRoot $state `
  -ConfirmLabMutation `
  -LabConfirmation CREATE_AND_REMOVE_ISOLATED_HYPERV_LAB_NETWORK
```

当前普通 Codex 沙箱通常不是管理员。不要通过非管理员会话声明 Lab PASS。

## 唯一身份

创建前记录生产适配器稳定身份，拒绝测试地址碰撞。创建后 control record 保存：

- run ID；
- switch name、switch ID；
- management adapter GUID；
- 两枚固定地址。

后续每个地址、生产指纹和清理操作都同时核验 switch ID 与 adapter GUID。清理不能按名称模糊匹配，也不能接管其他运行遗留资源。若交换机已不存在但 adapter 或测试地址仍存在，结果是 `MANUAL_RECOVERY_REQUIRED`。

## 生产指纹

setup、恢复和完成后比较预先选定的稳定生产对象：物理/默认出口适配器、TUN、相关地址、路由、DNS、WinINET 实际值、WinHTTP 和 FlClash 进程身份。动态 Teredo 等无关接口不加入全量字节比较。指纹变化时停止测试，只清理本次准确拥有资源，不自动恢复生产配置。

## 快照与故障

地址创建后写入 `LabAddressSnapshot`，同时生成独立 SHA-256 manifest。恢复顺序固定：

1. 路径和大小限制；
2. 字节 SHA-256；
3. JSON Schema；
4. switch/adapter/run identity；
5. 地址白名单与属性；
6. 当前 ownership；
7. 只补回缺失地址并等待 Preferred。

复制快照并追加一个字节必须得到 `rejected=true`、`zeroMutation=true`。删除准确地址后，Socket 必须出现 `failedStage=bind`、native error `10049`、`connectAttempted=false`；恢复后 nonce echo 再 PASS。

Worker 中断测试只删除本次 IPv4 地址并以固定非零码退出。父进程独立读取 current state，按可信快照只补回缺失地址，不重放整段写操作。该测试不覆盖主机重启、断电、父进程崩溃或 Watchdog 自身崩溃。

## 输出与清理

run directory 至少包含：

- `control.json`
- `production-before.json`
- `lab-address-snapshot.json`
- `lab-address-snapshot.manifest.json`
- IPv4/IPv6 before/fault/restored 结果
- 损坏快照与中断恢复结果
- `cleanup.json`
- `done.json`
- `result.json`

`result.json` 只有必需测试与精确清理均成功时才为 `PASS`。`cleanupVerified=true` 需要循环确认精确 switch ID、adapter GUID 和两枚地址都不存在。清理或清理验证失败时，`done.json` 与 `result.json` 都使用 `MANUAL_RECOVERY_REQUIRED`，保留现场并停止新的自动写测；普通测试失败仍为 `FAIL`。

旧 `attempt3` 证明前身 harness 的 9/9 管理员实机路径，但它不是 v0.2.0 Skill 的复测证据。最终候选若未重新运行，manifest 必须保持 `isolatedLabLive=NOT_RUN`。

创建交换机前先记录 creation intent 并等待 watchdog readiness。交换机返回后立即持久化精确 GUID；控制记录建立前发生查询、删除或验证异常也会写 `cleanup-error.json`、`done.json`、`result.json`，终态为 `MANUAL_RECOVERY_REQUIRED`。若进程在交换机创建与 GUID 落盘之间退出，watchdog 仅记录人工恢复，禁止凭名称猜测删除。磁盘不可写、宿主重启或 watchdog 同时终止仍需带外恢复；本版本没有实际验证这些故障。
