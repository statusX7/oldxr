# PHASE 8：按 inbound tag 索引用户流量 counter

## 基本信息

- 日期/时区：2026-08-18 14:35 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 8 / global stats scan 与首次并发注册
- branch：`perf/stats-index`
- 修改前 HEAD：`46ace5a`（`main`）
- 本报告对应 commit：提交后以 Git 历史为准
- Go version：`go1.20.14 linux/amd64`
- xray-core：`v1.7.5`，未升级
- 测试环境：Debian 12、AMD EPYC 9534、8 vCPU、约 15 GiB RAM、linux/amd64

## 问题背景与代码证据

原调用链：

```text
app/mydispatcher.DefaultDispatcher.getLink
→ stats.GetOrRegisterCounter
→ xray-core app/stats.Manager.counters
→ Controller.collectTrafficByCounterVisit
→ Manager.VisitCounters
→ strings.Split(name, ">>>")
→ tag filter
→ drainTrafficCounter
→ ReportUserTraffic
```

证据位置：

- `app/mydispatcher/default.go::getLink()`：每条有用户 stats 的连接分别构造 uplink/downlink counter name，并调用 `stats.GetOrRegisterCounter`；
- `service/controller/controller.go::collectTrafficByCounterVisit()`：每个 Controller 对全局 counter map 完整执行 `VisitCounters`；
- xray-core v1.7.5 `app/stats/stats.go::VisitCounters()`：持有全局 `Manager.access.RLock` 遍历完整 `counters` map；
- 同文件 `RegisterCounter()`：需要全局写锁，因此长扫描会阻塞新 counter 注册；
- xray-core v1.7.5 `features/stats.GetOrRegisterCounter()`：`GetCounter` 与 `RegisterCounter` 不是一个原子操作，并发第一次注册时 loser 会收到 error/nil，原 dispatcher 会让该连接缺少对应 `SizeStatWriter`。

原复杂度约为：

```text
O(controller count × global counter count)
```

而且即使 counter 已经归零，`strings.Split` 及全局 map visit 仍会发生。

## 修改前基线

新增 `BenchmarkCollectTrafficByCounterVisit`，矩阵覆盖：

```text
counters:   1k / 10k / 50k
controllers: 1 / 10 / 100
stale:       0% / 50% / 90%
```

这里 stale 定义为仍注册但本轮值为零的历史 counter；active counter 在每轮设为 1。`global` 与 `indexed` 在同一个 binary、同一 fixture 下比较，避免跨 commit 机器噪音。

修改前代表性结果（`GOMAXPROCS=1`）：

| counters | controllers | stale | ns/op | B/op | allocs/op | counter visits/op |
|---:|---:|---:|---:|---:|---:|---:|
| 1k | 1 | 90% | 中位数 301,438 | 约 78,448 | 约 1,070 | 1,000 |
| 10k | 10 | 50% | 中位数约 29,509,000 | 约 7,704,000 | 约 105,380 | 100,000 |
| 50k | 100 | 90% | 中位数约 1,475,169,000 | 约 321,146,000 | 约 5,006,975 | 5,000,000 |

50k/100/90% stale 的 CPU profile 采样 1.59 s：

```text
indexbody               flat 46.54%
strings.genSplit        cum  74.21%
collect func2           cum  85.53%
runtime.mallocgc        cum  13.21%
```

alloc_space profile 中 `strings.genSplit` 单轮约 287 MB，占样本 89.71%，证明主要 allocation 不是 traffic payload，而是每个 Controller 重复解析所有全局 counter name。

## 修改方案

### tag-local counter index

在 `DefaultDispatcher` 内新增 `userTrafficCounterIndex`：

- 第一层用 `sync.Map` 按 inbound tag 分区；
- 每个 tag 使用独立 `RWMutex` 和 `map[taggedEmail]*userTrafficCounterPair`；
- 同一用户的 uplink/downlink counter 放在一个 pair，避免两个索引 map entry；
- connection hot path 先按 `taggedEmail` 命中已缓存 counter reference，不再重复构造完整 stats name，也不再访问 xray-core 全局 stats map；
- 首次 miss 才构造 legacy counter name 并注册；
- 若 `RegisterCounter` 因外部并发 registrar 失败，会重新 `GetCounter`，不会仅因 counter 已存在而让连接漏挂 `SizeStatWriter`；
- traffic collection 只访问当前 inbound tag 的 pair，不再持有 xray-core 全局 stats lock；
- Controller 保留原 `VisitCounters` fallback，供不支持 tag index 的测试或兼容实现使用。

### traffic semantics

索引仅保存 xray-core v1.7.5 `stats.Counter` reference；实际计数、原子 drain、失败恢复和 V2Board traffic payload 都保持不变：

```text
counter.Set(0)
→ delta
→ ReportUserTraffic
→ failure: counter.Add(delta)
```

未在用户删除时调用 `UnregisterCounter`，因为已经建立的长连接仍持有 `SizeStatWriter` 和 counter reference。此时删除 manager/index entry 会让连接稍后新增的字节永久失去收集入口，违反计费守恒。

## 修改文件

- `app/mydispatcher/default.go`
- `app/mydispatcher/traffic_stats.go`
- `app/mydispatcher/traffic_stats_test.go`
- `service/controller/controller.go`
- `service/controller/traffic_accounting_test.go`
- `service/controller/traffic_stats_benchmark_test.go`
- `docs/engineering-reports/20260818-1435-perf-stats-index.md`

## 正确性与并发测试

新增覆盖：

- 100 goroutine 同时首次注册同一 counter，全部得到同一非 nil counter；
- tag-local visit 不泄漏其他 Controller counter；
- visit 与 1,000 个新用户注册并发；
- indexed collection 只 drain 当前 tag；
- UID/email/uplink/downlink mapping 不变；
- 原 PHASE 2 成功、失败、panic、reset、连续 report 和并发字节守恒测试继续通过；
- fallback global visitor 测试继续通过。

定向 race：

```text
go test -race ./app/mydispatcher ./service/controller \
  -run 'Test(UserTrafficCounterIndex|CollectTrafficByIndexedVisit|Traffic)' \
  -count=20
PASS
```

## Benchmark before / after

`GOMAXPROCS=1`、相同 commit 内 global/indexed A/B、每个代表场景 `count=10`、`benchtime=1x`。

| 场景 | global 中位数 | indexed 中位数 | latency 变化 | B/op 约变化 | allocs/op 约变化 |
|---|---:|---:|---:|---:|---:|
| 1k counter / 1 Controller / 90% stale | 301.44 µs | 114.86 µs | -61.9% | 78.4 KB → 14.4 KB（-81.6%） | 1,070 → 69–70（约 -93.5%） |
| 10k / 10 / 50% stale | 29.51 ms | 2.256 ms | -92.4% | 7.70 MB → 1.30 MB（-83.1%） | 105,380 → 5,369（-94.9%） |
| 50k / 100 / 90% stale | 1.475 s | 6.412 ms | -99.57% | 321.15 MB → 1.142 MB（-99.64%） | 5,006,975 → 约 6,834（-99.86%） |

最后一个场景的 counter visit 从 5,000,000/op 降为 50,000/op，符合从全局重复扫描到 tag 分区的复杂度变化。

## Connection lookup hot path

`BenchmarkUserTrafficCounterLookup`，`GOMAXPROCS=8`：

```text
global-parallel: 69.76 ns/op, 64 B/op, 1 alloc/op
indexed-parallel: 33.18 ns/op, 0 B/op, 0 alloc/op
```

5 轮 200 ms 样本中 indexed serial 为约 29.2–32.3 ns/op、0 allocation；indexed parallel 为约 40.9–49.1 ns/op、0 allocation。global 路径每次为 64 B / 1 allocation，来自动态完整 counter name。

## CPU / memory / GC / lock

- CPU：以 `ns/op` 和 CPU profile 表征；global profile 的主要热点 `strings.genSplit` 已从 production indexed collection 消失；
- allocation：代表性 50k/100/90% stale 从约 321 MB/op 降到 1.14 MB/op；
- heap retained：未获得可靠 service-level retained heap 数据；benchmark 完成后 fixture 会释放，`inuse_space` 主要由 protobuf/AWS dependency init 占据；
- RSS：未测 / 无可靠数据；
- GC cycles/pause：未单独量化；每轮 allocation input 大幅下降，但不把它等同为已测得 GC pause 改善；
- goroutine：production 修改未新增 goroutine；
- mutex profile：单线程 collection 和 8 vCPU parallel lookup 均无可归因的 mutex delay sample；
- block profile：只有 Go benchmark harness 的 channel/WaitGroup 等待，没有 production index lock block sample。

索引新增 retained state：每个曾产生 user traffic counter 的 tag 保留一个 tag-local map，每个用户保留一个 pair 和 counter references。没有可靠 heap 数值，不声称净 retained heap 降低；本阶段收益是周期 allocation/CPU/全局锁范围和 connection lookup。

## stale counter 处理结论

xray-core v1.7.5 支持 `UnregisterCounter`，但仅从 manager map 删除名称，不能阻止现存 `SizeStatWriter` 继续写旧 pointer。用户删除不等于连接立即关闭，因此当前没有无损的安全清理时点。

本阶段明确不做以下危险优化：

```text
remove user
→ immediately UnregisterCounter
→ remove index pair
```

否则长连接在删除后新增的字节不会被后续 report 发现。安全清理需要 connection lifecycle/reference tracking，必须在 PHASE 9 或后续以独立正确性测试证明，不能仅凭 heap 目标实施。

## V2Board 1.6.0 兼容性影响

- `user_id/u/d` payload 不变；
- runtime tag 格式 `tag|email|uid` 不变；
- uplink/downlink counter name 不变；
- PHASE 2 atomic drain/restore 不变；
- V2Board API path、ETag、`LAST_CHECK_AT`、`LAST_PUSH_AT` 不变；
- VMess/Trojan/Shadowsocks authentication 不变；
- Go module、xray-core、dependencies 未改变。

## go test / vet / race / build

```text
go test ./...       PASS
go vet ./...        PASS
go test -race ./... PASS
go build ./...      PASS
```

首次 sandbox 内全仓库 race 因 `httptest` 无权执行 `listen tcp6 [::1]:0` 失败；在允许 loopback 的隔离权限下用完全相同命令重跑通过。该环境限制及重跑结果均保留，不将其伪装成第一次成功。

## Release 状态

- Release/tag：未创建；
- `v0.9.0`：未移动；
- 本阶段通过 Gate 后才 push 工作分支并 fast-forward `main`。

## 已知风险与未解决问题

1. index 与 xray-core manager 同时持有 counter reference，会增加少量 retained metadata；尚无可靠 heap 数值。
2. 同一个 tag 内 traffic collection 持有 tag-local `RLock`；它不会阻塞已存在用户 lookup，但会短暂阻塞该 tag 的首次 counter registration。mutex/block profile 未观察到样本，仍需 service soak 验证。
3. stale user counter 不能在没有 connection lifecycle 证据时安全删除，retained counter 数仍可能随历史用户增长。
4. node tag reload 后旧长连接的 traffic lifecycle 属于既有 reload/rollback 问题，本阶段未扩大修改范围。
5. benchmark 是 synthetic counter/controller workload，不等同真实协议 throughput 或 100-user production traffic。

## 下一步

- PHASE 9：对 dispatcher connection setup 做 profile/microbenchmark，只保留有数据的 string/lookup/allocation 优化；
- PHASE 10：先修 RuleManager correctness，再决定 `MatchString`；
- PHASE 11/12：在 1C1G 近似约束和 soak 中观察 index retained heap、counter slope、RSS、GC、goroutine、fd；
- 若要清理 stale counter，必须先建立 active writer lifecycle 和 total byte conservation fixture。
