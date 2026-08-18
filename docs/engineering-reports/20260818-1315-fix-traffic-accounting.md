# PHASE 2：修复流量上报并发丢失窗口

## 基本信息

- 日期/时区：2026-08-18 13:15 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 2，P0 traffic accounting correctness
- branch：`fix/traffic-accounting`
- baseline HEAD：`585f70e79d643543592e1e9f0941184a79a8cde5`
- Go version：`go1.20.14 linux/amd64`
- xray-core version：`github.com/xtls/xray-core v1.7.5`
- 测试环境：Debian 12、linux/amd64、8 vCPU、15 GiB RAM
- benchmark：`GOMAXPROCS=1`、相同 toolchain/cache、`-count=10`

## 问题背景

原流量链路为：

```text
stats.Counter.Value()
→ api.UserTraffic
→ HTTP ReportUserTraffic
→ resetTraffic
→ stats.Counter.Set(0)
```

`Value()` 与成功后的 `Set(0)` 不是同一个原子事务。xray-core 的 dispatcher 可在 HTTP 请求期间继续对同一 counter 执行 `Add()`；这些新增字节随后会被 `Set(0)` 覆盖，形成永久少计费。

涉及路径：

- `service/controller/controller.go::collectTrafficByCounterVisit`
- `service/controller/controller.go::userInfoMonitor`
- `service/controller/control.go::getTraffic`
- `service/controller/control.go::resetTraffic`

## 修复前确定性证据

先加入 barrier test，让顺序固定为：

```text
counter = 100
report goroutine Value() = 100
并发 Add(7)
允许成功路径 Set(0)
检查 reported + remaining
```

修复前实际结果：

```text
--- FAIL: TestTrafficResetConservesConcurrentIncrement
traffic is not conserved: reported + remaining = 100, want 107
```

这不是概率性 race detector 结果，而是确定性证明 7 bytes 被覆盖。

## 一级实现证据

xray-core v1.7.5 `features/stats.Counter` 明确约定：

- `Set(int64)` 设置新值并返回旧值；
- `app/stats.Counter.Set` 使用 `atomic.SwapInt64`；
- `Add(int64)` 使用 `atomic.AddInt64`。

因此可以在不修改 xray-core 的情况下原子提取一个 reporting delta。

## 根因

原实现把“读数”和“提交后清零”分成两个原子操作，中间跨越不受控 HTTP 延迟；即使每个单独操作线程安全，组合操作仍不满足流量守恒。

## 修改方案

1. 使用 `Counter.Set(0)` 的返回值在采集时原子 drain，而不是先 `Value()`、成功后再清零。
2. 记录每个被 drain 的 `trafficCounterDelta{counter, value}`。
3. HTTP 成功时直接提交该 delta；swap 后到达的新字节留在 counter，进入下一轮。
4. HTTP 返回 error 时，对精确 delta 执行 `Counter.Add(value)`；它与 swap 后的新流量相加，不会覆盖后续增量。
5. reporter panic 时通过 `defer` 执行同一恢复逻辑，然后继续传播 panic。
6. `DisableUploadTraffic=true` 时仍 drain 并丢弃，保持原 legacy 行为。
7. 负 counter 不作为流量上报，并恢复其原值，避免本修复意外改变异常状态语义。
8. global counter visitor 先验证当前 controller tag 和 `uplink/downlink` direction，再 drain，保证其他 controller/未知 counter 不被修改。

没有引入 pending map、持久 cache、锁、channel 或 goroutine。

## 修改文件

- `service/controller/control.go`
- `service/controller/controller.go`
- `service/controller/traffic_accounting_test.go`
- `docs/engineering-reports/20260818-1315-fix-traffic-accounting.md`

## 兼容性影响

保持不变：

- V2Board 1.6.0 submit route；
- JSON `user_id/u/d`；
- UID/email/tag 映射；
- uplink/downlink 方向；
- auto speed limit 使用当前 reporting interval bytes 的语义；
- `DisableUploadTraffic` 的 legacy discard 行为；
- VMess/Trojan/Shadowsocks API 和认证语义；
- Go module、依赖、xray-core 和 config.yml。

改变的是内部 counter 提取时序：从非原子的 read-later-reset 改为 atomic drain-with-restore。

## 正确性测试

新增/覆盖场景：

- drain 后、HTTP 成功前的并发 `Add`；
- HTTP report error 时 uplink/downlink 全量恢复；
- 第一次失败、恢复后第二次成功；
- 连续三轮成功 report，无遗漏、无重复；
- report in-flight 期间 counter reset 后的恢复；
- 8 goroutine 共 80,000 次并发 `Add` 与持续 drain 的总量守恒；
- reporter panic 恢复；
- `DisableUploadTraffic` 不调用 reporter 且保持 discard；
- 负 counter 保持原值；
- 真实 xray stats manager 中只 drain 当前 controller 的有效 uplink/downlink counter。

定向 race stress：

```bash
go test -race -count=20 -timeout=5m -run '^(TestTraffic|TestCollectTraffic)' ./service/controller
```

结果：通过，未报告 data race。

## go test

```bash
go test -count=1 -timeout=5m ./...
```

结果：通过。

## go vet

```bash
go vet ./...
```

结果：通过。

## race

```bash
CGO_ENABLED=1 go test -race -count=1 -timeout=10m ./...
```

结果：通过，未报告 data race。

## benchmark before / after

命令：

```bash
GOMAXPROCS=1 go test -run '^$' -bench '^BenchmarkTrafficCounterCycle$' -benchmem -count=10 ./service/controller
```

该 benchmark 测量一次 counter `Add` 加一次 reporting cycle；before 是 `Add + Value + Set(0)`，after 是 `Add + Set(0)` atomic drain。

| 指标 | before | after | 变化 |
| --- | ---: | ---: | ---: |
| 中位数 ns/op | 5.996 | 5.397 | 约 -10.0% |
| 样本范围 ns/op | 5.840–6.366 | 5.168–5.721 | 下降 |
| B/op | 0 | 0 | 不变 |
| allocs/op | 0 | 0 | 不变 |

未安装 `benchstat`，本表按 10 个原始样本计算中位数；没有把微基准变化写成整机 CPU 改善。

## CPU / memory / GC

- 全进程 CPU：未测 / 无可靠数据
- RSS：未测 / 无可靠数据
- heap：未测 / 无可靠数据
- counter hot-path `B/op`：0 → 0
- counter hot-path `allocs/op`：0 → 0
- goroutine：实现未新增 goroutine；未做全进程计数
- GC cycles/pause：未测 / 无可靠数据
- mutex/block：实现未新增 mutex/channel；未采集 profile

## build 结果

```bash
CGO_ENABLED=0 go build -trimpath -o /tmp/oldxr-phase2-traffic-accounting ./main
```

- 结果：通过
- size：125,219,512 bytes
- SHA256：`621f3202c3a6b956fae457fce035cb4cd54984c7ac0e11a75113b32ffd0ef494`
- `go version -m`：Go 1.20.14、linux/amd64、xray-core v1.7.5、`CGO_ENABLED=0`

## Release 状态

不适用。本阶段不创建 tag、asset 或 Release。

## 已知风险与边界

1. 如果 panel 已处理请求，但客户端因连接中断只看到 error，V2Board 1.6.0 没有 idempotency key/ack protocol，重试可能重复计费；这是 legacy API 的 at-least-once 模糊失败边界，本修复没有扩大它，也不能仅靠节点端彻底消除。
2. failure restore 使用被 drain 的同一个 counter object。Controller runtime reload 若在 report 期间替换/注销 counter，恢复到旧对象可能无法进入后续扫描；PHASE 4 必须通过 state ownership/serialization 消除 reload-report 交叉窗口，Release Gate 前不能忽略。
3. 进程在 atomic drain 后、HTTP 完成或恢复前被强制终止，内存 counter 仍会丢失；旧实现和 xray-core 内存统计本就没有 crash persistence。若未来需要 crash-exact accounting，必须引入持久 WAL 和 panel 幂等协议，不能在本次最小修复中假装解决。
4. 同一 batch 被多个 reporter 并行提交会破坏一次性恢复假设；当前 `userInfoMonitor` 是该 batch 的 owner，PHASE 4 会把 ownership 写入并发模型和 stress fixture。

## 未解决问题

- P0 same UID modified user。
- P0 Controller shared state/reload-report race。
- P0/P1 Global IP/Device Limit。
- legacy panel ambiguous failure 的 exactly-once 上报无法由当前 API 单边保证。

## 下一步

进入 PHASE 3：修复相同 UID 属性变化的 diff，分别验证 runtime identity change 与 limit-only change，并建立 1k/10k/50k 用户 benchmark。
