# PHASE 9：Dispatcher connection setup 性能验证

## 基本信息

- 日期/时区：2026-08-18 14:40 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 9 / dispatcher connection hot path
- branch：`perf/dispatcher`
- 修改前 HEAD：`871441f`（`main`）
- 本报告对应 commit：提交后以 Git 历史为准
- Go version：`go1.20.14 linux/amd64`
- xray-core：`v1.7.5`，未升级
- 测试环境：Debian 12、AMD EPYC 9534、8 vCPU、约 15 GiB RAM、linux/amd64

## 问题背景

PHASE 8 已把每连接 user stats counter lookup 从：

```text
construct full counter name
→ xray global stats map RLock/Get
```

改为 tag-local indexed reference，8 vCPU parallel lookup 从约 `69.76 ns/op, 64 B/op, 1 alloc/op` 降为约 `33.18 ns/op, 0 B/op, 0 alloc/op`。

本阶段继续检查 `app/mydispatcher.DefaultDispatcher.getLink()` 的实际 connection setup 成本，避免仅凭 `grep fmt.Sprintf` 修改低频日志或 failure path。

## 调用链与静态证据

```text
Dispatch
→ getLink
→ pipe.OptionsFromContext
→ pipe.New × 2
→ Limiter.GetUserBucket
→ optional RateWriterContext × 2
→ optional traffic counter lookup × 2
→ optional SizeStatWriter × 2
→ routedDispatch goroutine
→ optional RuleManager.Detect
→ router / outbound handler
```

审查结果：

- `fmt.Sprintf` 位于 UDP FakeDNS debug log、rule rejection error、tag/build 等路径，不是普通 TCP connection setup 的无条件热点；
- `strings.Split` 的主要周期热点已在 PHASE 8 的 global stats scan 中移出 production path；
- `GetUserBucket` 仍必须取得 source IP 并维护 legacy online/device semantics，不能在 limit=0 时直接跳过；
- `RateWriterContext` 和 `SizeStatWriter` 都保存该连接独立 writer/counter/context，生命周期与连接绑定；
- `Dispatch` 每连接启动 routed goroutine 是现有 xray dispatcher ownership 模型，本阶段没有证据支持在 v1.7.5 基线上改写。

## Benchmark fixture

新增 `BenchmarkDispatcherGetLink`：

- TCP、sniffing off；
- 固定 authenticated user 与 source IP；
- 在 timer 外 prime device、rate limiter、stats counter；
- timer 内创建两组 pipe/link、执行 limiter/stats wrapping，并立即关闭 benchmark link；
- 场景覆盖 anonymous、stats on/off、speed limiter on/off；
- 不创建真实 socket，不等同协议握手或完整 router/outbound throughput。

## Benchmark 结果

`GOMAXPROCS=1`，代表性中位数：

| 场景 | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| anonymous | 约 973 | 936 | 22 |
| authenticated / stats off / limiter off | 约 1,187 | 952 | 24 |
| authenticated / stats on / limiter off | 约 1,310 | 1,016 | 26 |
| authenticated / stats off / limiter on | 约 1,349 | 1,048 | 26 |
| authenticated / stats on / limiter on | 约 1,588 | 1,112 | 28 |

时间样本受 GC 和 benchmark calibration 影响，尤其 full feature 约 1.38–1.96 µs；B/op 与 allocs/op 在重复样本中稳定。

可分离的固定增量：

```text
stats two SizeStatWriter:      +64 B/op, +2 allocs/op
limiter two RateWriterContext: +96 B/op, +2 allocs/op
```

## CPU / allocation profile

full feature、`GOMAXPROCS=1`、2 s benchmark：

```text
1,745 ns/op
1,112 B/op
28 allocs/op
```

CPU profile（4.12 s samples）：

```text
runtime.mallocgc        flat 12.86%, cum 57.77%
runtime.newobject       cum  40.29%
DefaultDispatcher.getLink cum 90.29%
runtime.makechan        cum  21.12%
```

alloc_space（2.40 GB total）：

```text
signal.NewNotifier      38.07%
signal/done.New         21.27%
pipe.New                cum 77.13%
getLink                 cum 99.86%
RateWriterContext        8.23%
```

因此剩余主要 allocation 属于 xray-core v1.7.5 `pipe.New` 的 per-link channel/notifier/done 状态，而不是 oldxr 重复 string construction。

## 修改决策

本阶段生产源码修改：`0`。

不实施以下无证据或高风险方案：

- pool `pipe.Reader` / `pipe.Writer` / notifier：连接关闭、interrupt、buffer 和 context 状态很容易跨连接泄漏；
- pool `RateWriter` / `SizeStatWriter`：wrapper 在长连接期间持续被引用，安全归还时点不明确；
- limit=0 时跳过 `GetUserBucket`：会改变 online/device legacy semantics；
- 默认关闭 stats/rule/sniffing：会改变用户配置行为；
- 重写每连接 routed goroutine：属于 xray-core dispatcher 生命周期设计，缺少 correctness/profile 依据。

本阶段仅提交 deterministic Benchmark 和工程报告。PHASE 8 已完成的 counter lookup 优化继续作为当前 baseline，不在本报告重复声称一次生产收益。

## Benchmark before / after

未修改 production code，因此 before/after 不适用；不存在为了“完成优化”而选择性展示的 after。当前数据作为后续 connection lifecycle、1C1G 和 soak 的正式 baseline。

## 兼容性影响

- production behavior：无变化；
- V2Board 1.6.0 API/traffic/user/tag：无变化；
- limiter、stats、sniffing、rule config：无变化；
- Go module、xray-core、dependencies：无变化。

## go test / vet / race / build

```text
go test ./...       PASS
go vet ./...        PASS
go test -race ./... PASS
go build ./...      PASS
```

## CPU / memory / GC / goroutine / lock 结论

- CPU：microbenchmark/profile 如上；
- B/op / allocs/op：如矩阵；
- retained heap：未测 / 无可靠 service-level 数据；
- RSS：未测 / 无可靠数据；
- GC cycles/pause：未单独测量；profile 表明 allocation/GC 是主要成本，但不能据此声称 pause 数值；
- goroutine：fixture 直接测 `getLink`，不包含 `Dispatch` 的 routed goroutine；production 未新增 goroutine；
- mutex/block：本阶段没有共享状态修改；PHASE 8 parallel lookup profile 未观察到 production lock delay sample；
- throughput / connection setup latency：这里只测内存内 `getLink` microbenchmark，不代表真实协议连接 latency/throughput。

## Release 状态

- Release/tag：未创建；
- `v0.9.0`：未移动；
- 本阶段仅在 Gate 通过后 push benchmark/report 分支并 fast-forward `main`。

## 已知风险与未解决问题

1. xray-core pipe per-connection allocation 是目前最大 setup allocation；基线固定为 v1.7.5，不能通过依赖升级规避。
2. 真实协议 handshake、router、outbound、sniffing、UDP FakeDNS 未包含在此 fixture。
3. connection goroutine、long-lived retained pipe memory、fd/RSS 需要 PHASE 11/12 synthetic service test。
4. RuleManager `Match([]byte)`、empty update、invalid regexp、HTTP 400 属于 PHASE 10 correctness/benchmark。

## 下一步

进入 PHASE 10：先用 deterministic tests 修 correctness candidate，再以 `Match`/`MatchString` benchmark 决定是否保留 micro optimization；之后执行 1C1G 近似与 soak，而不是继续压缩 xray-core pipe 对象。
