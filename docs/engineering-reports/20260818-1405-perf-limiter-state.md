# PHASE 6：Limiter 生命周期、限速正确性与分配优化

## 基本信息

- 日期/时区：2026-08-18 14:05 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 6 / limiter lifecycle、allocation、RateWriter
- branch：`perf/limiter-state`
- 修改前 HEAD：`84d9900`（`main`）
- 本报告对应 commit：提交后以 Git 历史为准
- Go version：`go1.20.14 linux/amd64`
- xray-core：`v1.7.5`，未升级
- 测试环境：Debian 12、AMD EPYC 9534、8 vCPU、约 15 GiB RAM、linux/amd64

## 问题背景与证据

### deleted user retained state

旧 `nodeInfoMonitor` 删除 runtime user 后，没有从 limiter 删除：

- `InboundInfo.UserInfo`；
- `InboundInfo.BucketHub`；
- `InboundInfo.UserOnlineIP`。

因此同一个 inbound 长期 user churn 时，历史 email/UID key 会留到整个 inbound reload。1000 active users、每轮替换 900 个用户的模型中，旧路径理论上每轮继续增长 900 个 `UserInfo`；已建立 map-entry fixture 作为 retained state 直接证据。

### rate.Limiter loser allocation

旧 `GetUserBucket` 在 speed limit 开启时先执行 `rate.NewLimiter`，再 `LoadOrStore`。existing user/IP 的每次新连接都会创建并丢弃 candidate。

修改前 `BenchmarkLocalLimiterExistingIPWithSpeedLimit`，`GOMAXPROCS=1`、`count=10` 中位数：

```text
214.45 ns/op
96 B/op
2 allocs/op
```

### RateWriter correctness

旧实现：

```go
w.limiter.WaitN(context.Background(), int(mb.Len()))
return w.writer.WriteMultiBuffer(mb)
```

`rate.Limiter.WaitN` 在 `n > burst` 时返回错误。旧代码忽略该错误并立即写出整个 MultiBuffer，因此大于 burst 的 write 可以绕过 speed limit；`context.Background()` 也使 connection context cancel 无法终止等待。

## 根因

1. controller 的 delete 流程只操作 xray runtime user，没有同步 limiter ownership；
2. limiter 只有 add/update/inbound delete，没有 per-user delete API；
3. speed bucket 查找采用 eager allocate；
4. rate writer 假设单次 MultiBuffer 永远不超过 burst，且忽略 `WaitN` error；
5. runtime key 反复使用 `fmt.Sprintf`，大批量 cleanup 产生额外 allocation。

## 修改方案

### per-user cleanup

- 新增 `Limiter.DeleteInboundLimiterUsers`；
- 在同一个 user shard lock 内删除 `UserInfo`、`BucketHub`、`UserOnlineIP`；
- controller 只有在 xray `removeUsers` 成功后才清理 limiter；
- `GetUserBucket` 先取得 user shard lock，再读取 `UserInfo`、更新 IP state、取得/创建 bucket；
- deleted user 不再以 uid=0 的 unknown state 被重新加入；
- 并发 connection 与 delete 的线性化保证：connection 先完成则 delete 最后清理；delete 先完成则 connection 发现 UserInfo 不存在且不重建状态；
- active connection 已持有的 bucket pointer 不被修改或强制关闭，只从新连接 lookup map 移除。

### bucket allocation

- 同一 user 的 bucket 操作已由 shard lock 保护；
- 先 `BucketHub.Load`，仅首次缺失才 `rate.NewLimiter`；
- 不再需要 existing path 的 loser allocation 和第二次 `LoadOrStore`。

### RateWriter

- 保留原 `RateWriter(writer, limiter)` API，并新增 `RateWriterContext`；dispatcher 使用 connection `ctx`；
- 单次 bytes 大于 burst 时按 `burst` 分块执行 `WaitN`；
- 任一 `WaitN` error 直接返回，不调用 underlying writer；
- connection cancel 能中断仍需等待 token 的 write；
- nil context 仅作为防御性 fallback 使用 `context.Background()`。

### key allocation

- 新增 `formatUserKey`，使用 `strings.Builder` + stack `strconv.AppendInt`；
- Add/Update/Delete 复用同一 key 构造；
- 保持 `<tag>|<email>|<uid>` 格式完全不变。

## 修改文件

- `common/limiter/limiter.go`
- `common/limiter/limiter_test.go`
- `common/limiter/rate.go`
- `common/limiter/rate_test.go`
- `service/controller/control.go`
- `service/controller/controller.go`
- `app/mydispatcher/default.go`
- `docs/engineering-reports/20260818-1405-perf-limiter-state.md`

## 兼容性影响

- runtime email/tag、UID、DeviceLimit、SpeedLimit 语义未改变；
- speed limited connection 仍共享 per-user `rate.Limiter`，uplink/downlink 仍使用同一 bucket；
- active connection 不因 user state cleanup 被主动关闭；
- 删除认证用户后，新 dispatch 不再重建 limiter state；
- V2Board API、traffic、online payload 未改变；
- Go/xray-core/dependencies 未升级。

## 正确性与并发测试

新增：

- `TestDeleteInboundLimiterUsersCleansRuntimeState`；
- `TestDeleteInboundLimiterUsersConcurrentWithConnections`；
- `TestDeleteInboundLimiterUsersChurnDoesNotRetainHistory`；
- `TestLimiterRepeatedUserChurnHasBoundedState`；
- `TestRateWriterSplitsWritesLargerThanBurst`；
- `TestRateWriterHonorsCanceledContext`。

重点结果：

```text
1000 active users
每轮删除/新增 900 users
20 cycles

每一轮：
UserInfo     = 1000
BucketHub    = 1000
UserOnlineIP = 1000
```

即 fixture 历史上经历 19,000 个 UID 后，retained entry 仍只等于 active users。定向 race（connection/delete/rate/churn）`count=20`：PASS。

## Benchmark before / after

### speed-limited existing IP

`GOMAXPROCS=1`、`count=10`：

| 指标 | before 中位数 | after 中位数 | 变化 |
|---|---:|---:|---:|
| `ns/op` | 214.45 | 132.45 | -38.24% |
| `B/op` | 96 | 0 | -100% |
| `allocs/op` | 2 | 0 | -100% |

该 benchmark 包含 PHASE 5 local IP lookup/shard lock；本阶段变量主要是 speed bucket lookup。

### user cleanup key path

`GOMAXPROCS=1`、`benchtime=3x`、`count=3`。短 benchtime 的时间噪音较大，allocation 更稳定。

| 用户数 | before 中位数 | after 中位数 | before B/op | after B/op | before allocs/op | after allocs/op |
|---:|---:|---:|---:|---:|---:|---:|
| 1k | 526.7 µs | 213.3 µs | 151,794 | 113,826 | 4,329 | 1,584 |
| 10k | 5.46 ms | 2.68 ms | 1,544,968 | 1,147,077 | 46,329 | 16,585 |
| 50k | 41.55 ms | 20.56 ms | 7,730,949 | 5,732,896 | 232,998 | 83,252 |

粗略中位数变化约：时间 -50% 到 -60%，B/op -26%，allocs/op -64%。由于 count=3 且 10k before 有一次 28 ms outlier，时间百分比只作为 microbenchmark 方向，不作为生产延迟保证。

## allocation / heap profile

fixture：10 次 `1000 active / 每轮 churn 900 / 20 cycles`，`memprofilerate=1`。

alloc_space 总计：`251.62 MB`。主要分配：

```text
sync.(*Map).Swap             60.34 MB flat
sync.(*Map).dirtyLocked      41.56 MB flat
strings.(*Builder).grow      25.59 MB flat
Limiter.GetUserBucket       125.70 MB cum
rate.NewLimiter              14.50 MB flat
Limiter.UpdateInboundLimiter 32.93 MB cum
```

这里的 `rate.NewLimiter` 对应每轮真正新增的 900 active users，不是 existing connection loser。fixture 总计创建大量真实新状态，因此 alloc_space 高是预期的 churn cost。

测试结束强制 GC 后 `inuse_space` 仅约 `31.20 kB`，测试 local limiter 已离开作用域，不能把该数字当生产 active-state heap。retained 正确性以每 cycle 三张 map 的精确 entry count 证明；RSS/active heap 仍需 PHASE 11/12 service-level fixture。

## go test

```text
go test ./...
PASS
```

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

## build

```text
go build ./...
PASS
```

## CPU / memory / GC / goroutine

- CPU proxy：existing speed lookup 和 cleanup benchmark 如上；
- B/op / allocs/op：existing speed lookup归零；cleanup allocation 显著下降；
- retained state：20 cycles 精确保持 active count；
- RSS：未测 / 无可靠数据；
- active heap bytes：未测 / 无可靠数据；
- GC cycles / pause：未测 / 无可靠数据；
- goroutine：本阶段未增加 background goroutine；RateWriter 使用已有 connection context，不创建 goroutine。

## Release 状态

- Release/tag：未创建；
- `v0.9.0`：未移动；
- 完成 Gate 后推送 `perf/limiter-state`，再 fast-forward `main`。

## 已知风险

1. 每个真正新增且启用限速的 active user 仍必须分配一个 `rate.Limiter`；这是持久 bucket，不是可消除的 loser。
2. cleanup 不主动关闭 active connection；这是避免错误中断和持锁 Close 的刻意选择。
3. global Redis 对已删除用户的 key 不主动远程 Delete，而依赖 TTL；在 controller runtime lock 内做阻塞 Redis delete 风险更高。local inbound state已立即删除。
4. `sync.Map` 在 90% churn 下 alloc_space 仍高；替换为单锁 map 需要 connection/read/write benchmark 和 race 证据，当前不做架构重写。
5. `RateWriter` canceled 时返回 error 后 MultiBuffer ownership沿用 xray writer contract；没有在 wrapper 内擅自 Release，避免 caller double free。

## 未解决问题

- global msgpack decode allocation；
- V2Board ETag / 304；
- stats scan / counter cleanup；
- dispatcher string/counter construction；
- 1C1G、RSS、GC 和 soak。

## 下一步

进入 PHASE 7，以 V2Board 1.6.0 的真实 ETag/304 语义建立 1k/10k/50k fixtures；304 必须跳过 body decode/diff，并保持 `LAST_CHECK_AT`、错误处理和 controller 隔离。
