# PHASE 4：Controller 共享状态与任务生命周期并发修复

## 基本信息

- 日期/时区：2026-08-18 13:40 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 4 / P0 Controller concurrency
- branch：`fix/controller-race`
- 修改前 HEAD：`dd998ebcedacc6c8f2f02f5fb7379b47d4de3e62`
- 本报告对应 commit：提交后回填以 Git 历史为准
- Go version：`go1.20.14 linux/amd64`
- xray-core：`v1.7.5`，未升级
- 测试环境：Debian 12、AMD EPYC 9534、8 vCPU、约 15 GiB RAM、linux/amd64

## 问题背景

`service/controller/controller.go` 原来分别通过两个 `task.Periodic` goroutine 执行 `nodeInfoMonitor` 和 `userInfoMonitor`，证书任务又通过第三个 goroutine 执行。`nodeInfoMonitor` 直接替换 `c.nodeInfo`、`c.Tag` 和 `c.userList`，其余任务及日志、用户 tag 构建同时直接读取这些字段。

此外，xray-core v1.7.5 的 `task.Periodic.Close()` 只把 `running` 设为 `false` 并停止下一次 timer，不等待当前 `Execute()` 返回。旧实现还以 `go c.tasks[i].Start()` 启动任务，存在 `Close()` 已执行、尚未调度的 `Start()` 随后重新启动 timer 的生命周期窗口。Panel 随后关闭 core 时，尚未退出的 monitor 仍可能访问 core、limiter 或 stats。

## 复现证据

修改前增加定向并发 fixture，使 writer 模拟 `nodeInfoMonitor` 发布新 `nodeInfo`、`Tag`、`userList`，两个 reader 模拟 user/cert/log 路径。命令：

```bash
go test -race ./service/controller -run '^TestControllerStateRace$' -count=1
```

结果：失败，race detector 分别定位到：

- `Controller.logPrefix()` 读取 `nodeInfo`，与 writer 替换 `nodeInfo` 冲突；
- `Controller.buildUserTag()` 读取 `Tag`，与 writer 替换 `Tag` 冲突；
- `Controller.buildNodeTag()` 读取 `nodeInfo`，与 writer 替换 `nodeInfo` 冲突；
- reader 读取 `userList`，与 writer 替换 `userList` 冲突。

这是可重复的实际数据竞争，不是只凭静态代码推测。

## 根因

1. `nodeInfo`、`Tag`、`userList` 和 `clientInfo` 是一个逻辑状态，却被逐字段、无同步地发布，reader 既可能发生 data race，也可能看到跨版本组合。
2. node reload 的 handler/limiter/rule 修改与 user report 的 counter/limiter/rule snapshot 没有共同 ownership。
3. `task.Periodic.Close()` 不提供 in-flight wait 语义；旧调用方也没有自己的 `WaitGroup`。
4. user tag 构建在批量创建用户时隐式读取可变 `c.Tag`，一次 50k 用户构建理论上可能混入两个 tag 版本。

## 修改方案

### 一致状态快照

- 新增 `stateMu sync.RWMutex`；
- 用 `controllerSnapshot` 把 `clientInfo`、`nodeInfo`、`tag`、`userList` 作为一个版本发布；
- `snapshot()` 一次取得自洽版本，`publishState()` 一次替换完整版本；
- 发布后的 `NodeInfo` 和 user slice 只读使用，不原地修改；
- `logPrefix()`、`buildNodeTag()`、`buildUserTag()` 改为从快照读取；
- 批量 runtime user 构建显式传入局部 `tag`，避免每用户加锁，也避免一次批量更新混用两个 tag。

### Runtime ownership

- 新增 `runtimeMu`；
- node monitor 的 handler/user/limiter/rule apply 与 user monitor 的 counter/limiter/online/rule snapshot 串行；
- `GetNodeInfo`、`GetUserList`、`GetNodeRule`、`ReportNodeStatus`、`ReportUserTraffic`、online/illegal 回传均不在 `runtimeMu` 内执行；
- user monitor 先取得 `runtimeMu`，再取得状态快照，避免等待 reload 后继续使用已经失效的旧 tag；
- 临界区只覆盖本地 core/limiter/stats 状态，不持锁等待面板 HTTP。

### 可等待任务生命周期

- 用 controller 自有的 context/timer runner 替代 `task.Periodic`；
- 启动前一次性 `taskWG.Add(len(tasks))`，不存在 `Wait()` 与后续 `Add()` 竞争；
- `Close()` 先 cancel，再等待所有正在执行的任务返回；
- cancel 后不会再调度下一轮；
- `Close()` 可重复调用；
- 生产 API client 仍以现有 Resty timeout 约束正在进行的 HTTP。由于 `api.API` 目前不接受 context，本阶段不能中途取消已发出的 HTTP；`Close()` 会等待其在既有 timeout 内返回。

## 修改文件

- `service/controller/controller.go`
- `service/controller/userbuilder.go`
- `service/controller/traffic_accounting_test.go`
- `service/controller/controller_state_race_test.go`
- `docs/engineering-reports/20260818-1340-fix-controller-race.md`

## 兼容性影响

- V2Board API path、query、JSON 字段、traffic payload、UID/tag 格式均未改变；
- runtime user tag 仍为 `<inbound-tag>|<email>|<uid>`；
- VMess legacy `alterID` 选择逻辑未改变；
- node/user/user traffic 更新周期仍是“立即执行一次检查，然后在上一次执行完成后等待 `UpdatePeriodic`”；
- Go module identity、xray-core、`go.mod`、`go.sum` 未改变；
- HTTP 调用仍可并行，runtime apply 被明确串行；
- 未解决的 runtime reload rollback 问题没有在本阶段伪装成已解决。

## 正确性测试

新增：

- `TestControllerStateSnapshotConcurrentPublication`：writer 连续发布 10,000 个完整版本，两个 reader 验证 `nodeInfo`、tag、user list 始终属于同一版本；
- `TestControllerCloseWaitsForInFlightTask`：slow task 未释放时 `Close()` 必须阻塞；释放后 `Close()` 返回；cancel 后 task 调用次数保持 1；第二次 `Close()` 成功。

定向 race：

```text
go test -race ./service/controller \
  -run '^(TestControllerStateSnapshotConcurrentPublication|TestControllerCloseWaitsForInFlightTask)$' \
  -count=20

PASS
```

## go test

```text
go test ./...
PASS
```

沙箱内首次执行因不允许 `httptest` 绑定 `[::1]:0` 失败；在允许 loopback socket 的执行环境原命令通过。这不是源码或 fixture 随机失败。

## go vet

```text
go vet ./...
PASS
```

## race

```text
go test -race ./...
PASS
```

## Benchmark

Benchmark：`BenchmarkControllerStateSnapshot`，只测 read-only snapshot；结果为本阶段修复后的锁读取成本。修改前直接读共享字段存在 race，因此没有可作为正确实现基线的 before 数据，禁止把不安全 direct read 当成可采用方案。

`GOMAXPROCS=1`，`-benchmem -count=10`：

```text
中位数约 20.16 ns/op
0 B/op
0 allocs/op
```

`GOMAXPROCS=8`，`-benchmem -count=10`：

```text
中位数约 47.24 ns/op
0 B/op
0 allocs/op
```

该锁不在 dispatcher connection hot path；读者是低频 controller monitor、证书任务和日志。批量 user builder 使用局部 tag，不会为每个用户执行 snapshot lock。

## mutex / block profile

采集命令对 20 轮 adversarial fixture 开启 `mutexprofilefraction=1` 和 `blockprofilerate=1`。该 fixture 的 writer:reader 状态操作比例远高于生产控制面，用于暴露最坏竞争而不是模拟生产吞吐。

mutex delay：

```text
sync.(*RWMutex).Unlock   759.97 ms  71.13%
sync.(*RWMutex).RUnlock  308.41 ms  28.87%
总计                       1068.38 ms
```

block delay 中与 state lock 相关：

```text
sync.(*RWMutex).RLock   1072.92 ms
sync.(*RWMutex).Lock     514.18 ms
```

其余主要是测试主 goroutine 的 `WaitGroup.Wait` / `chanrecv1`。这些数据说明极端连续写入会产生预期 contention；实际生产写入按 panel update 周期发生，且连接数据面不读取该锁。后续 soak 仍需观察真实 controller 数量下的 mutex profile。

## CPU / memory / allocation / GC

- snapshot CPU proxy：见上述 `ns/op`；
- snapshot allocation：`0 B/op`、`0 allocs/op`；
- heap：未测 / 无可靠数据；本修复没有 per-connection 对象；
- RSS：未测 / 无可靠数据；
- goroutine：周期任务数量与旧实现相同（node/user，TLS 时另加 cert），但现在可取消、可等待；
- GC cycles / pause：未测 / 无可靠数据；
- retained memory：未测 / 本阶段无新的长期 cache。

## build 结果

```text
go build ./...
PASS
```

## Release 状态

- Release：未创建；
- tag：未创建；
- push：将在本阶段 commit 后推送工作分支，并通过 Gate 后 fast-forward `main`；
- `v0.9.0`：未移动。

## 已知风险

1. `api.API` 没有 context 参数，正在执行的面板 HTTP 不能被 `Close()` 主动取消；生产 client timeout 是退出上界。未来若改变接口必须保护全部 legacy adapter，不能在本修复中扩大范围。
2. node runtime reload 仍是先移除旧 handler 再创建新 handler，创建失败时没有 rollback；这是独立 P1 correctness/stability 项。
3. 极端频繁 state writer 会造成 `RWMutex` contention；当前锁不进入连接 hot path，但多 controller soak 仍要验证。
4. `Tag` 保留为 exported field 以避免破坏可能存在的 Go 调用方；仓库内所有读写已统一走 state lock。仓库外代码若直接读取该字段，仍应迁移到受控 accessor；当前项目内没有这类调用。

## 未解决问题

- Global IP/device limit plain map、边界和 goroutine 放大：PHASE 5；
- limiter retained state / per-connection allocation：PHASE 6；
- V2Board ETag / 304：PHASE 7；
- global stats scan / stale counter：PHASE 8；
- runtime reload rollback：后续独立阶段；
- 低配与 soak：PHASE 11/12。

## 下一步

进入 PHASE 5，先用 concurrent insertion、limit boundary、same/different IP、burst 和 global slow/unavailable fixture 证明 DeviceLimit 问题，再修改 `common/limiter`。不得把 controller 的 `runtimeMu` 扩展为连接数据面的全局锁。
