# PHASE 5：Global IP / DeviceLimit 正确性与 hot path 修复

## 基本信息

- 日期/时区：2026-08-18 13:55 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 5 / P0-P1 Global IP / DeviceLimit
- branch：`fix/global-ip-limit`
- 修改前 HEAD：`ef4ecaf`（`main`）
- 本报告对应 commit：提交后以 Git 历史为准
- Go version：`go1.20.14 linux/amd64`
- xray-core：`v1.7.5`，未升级
- 测试环境：Debian 12、AMD EPYC 9534、8 vCPU、约 15 GiB RAM、linux/amd64

## 问题背景

`common/limiter/limiter.go::GetUserBucket` 是连接建立 hot path。旧实现每次连接都先创建一个 `sync.Map` 并写入 IP，即使 email 已经存在；global 模式又采用 `Get -> 修改 map -> go pushIP`。第一次审计提出了 plain map race、边界错误和 goroutine 放大候选，本阶段以实际依赖实现和可复现测试重新验证。

## 证据与对旧判断的修正

### 已确认：global 边界错误

旧判断：

```go
if deviceLimit > 0 && len(*ipMap) > deviceLimit
```

当已有 IP 数正好等于 limit 时，新 IP 仍会被插入。修改前 deterministic test：

```text
TestGlobalDeviceLimitRejectsNewIPAtBoundary
FAIL: new IP was accepted when len(ipMap) == deviceLimit
```

### 已确认：concurrent lost update / 超额接受

100 个并发首次 IP、`deviceLimit=5`，修改前实际结果：

```text
accepted 21 concurrent IPs, limit is 5
```

不同 goroutine 各自执行 cache `Get`，再异步 `Set`，属于非原子的 read-modify-write；后写入的旧 snapshot 会覆盖其他 IP。

### 修正：没有通过真实 marshaler 路径复现 plain-map data race

gocache `marshaler.Get(ctx, key, new(map[string]int))` 会把 msgpack 解码到调用方每次新建的 map。因此本阶段没有证据支持“多个调用必然同时写同一个 Go map”。实际、已证明的问题是 lost update、边界错误和异步任务放大。报告不把旧审计候选写成已确认 race。

### 已确认：per-connection allocation

修改前 `BenchmarkLocalLimiterExistingIP`，`GOMAXPROCS=1`、`count=10` 中位数：

```text
579.15 ns/op
392 B/op
10 allocs/op
```

即使 IP 已存在，旧路径仍构造 loser `sync.Map` 并执行第一次 Store。

### 已确认：goroutine / cache 生命周期

旧 global 路径的两个新 IP 分支均执行 `go pushIP(...)`；Redis 慢时，待完成 goroutine 数与新 IP burst 成正比。`cache.NewChain` 自身还启动没有公开 Close 的 setter goroutine，patrickmn/go-cache janitor 也依赖 GC finalizer 才停止。limiter replace/delete 原来只删除 `sync.Map` entry，不显式关闭 Redis client。

## 根因

1. limit 判定使用 `>`，没有区分“same IP at capacity”和“new IP at capacity”；
2. local 模式先并发插入再计数，多 goroutine可能同时看到超限并全部回滚，无法保证精确接受 N 个；
3. global 模式没有 per-user ownership，cache read-modify-write 不原子；
4. global 写入用 unbounded detached goroutine 隐藏 Redis latency；
5. 每连接无条件构造 `sync.Map`；
6. global cache 组件没有跟随 inbound replace/delete 关闭。

## 修改方案

### local DeviceLimit

- 每个 inbound 使用 64 个固定 shard mutex；key 为完整 runtime email；
- 同一用户的新 IP 判定串行，不同用户大多数情况下并行；
- 先 Load email/IP；只有 email 首次出现时才创建 `sync.Map`；
- 新 IP 在插入前计数，`counter >= deviceLimit` 直接拒绝；
- same IP 在 limit 边界继续接受；
- `GetOnlineDevice` reset 同样取得相同 shard lock，避免 reset 与新连接跨 epoch 交错；
- 固定 64 shard 避免为历史用户永久保留一个 mutex map。

### global DeviceLimit

- 独立 64 shard mutex 保护每个 global unique key 的 `Get -> check -> Set`；
- same IP 先返回，再以 `len(ipMap) >= deviceLimit` 判断新 IP；
- 更新前复制 map，避免修改 cache 返回对象；
- `Set` 同步执行并受既有 `Timeout` context 限制，不再创建 detached goroutine；
- Get/Set 错误继续沿用 legacy fail-open，不因 Redis 故障突然拒绝全部用户；
- slow Set test 证明 caller 不会在后台写任务尚未结束时提前返回。

### 可关闭 layered cache

- 移除 `cache.NewChain`；
- Redis key 和 msgpack `map[string]int` 格式保持不变；
- remote hit 按 Redis 剩余 TTL 回填 local；
- local cache 使用有锁 map、lazy expiry 和每 256 次写入一次的过期 sweep，不创建 janitor goroutine；
- inbound replace/delete 时显式 `redis.Client.Close()`；
- local Set 成功但 Redis Set 失败时仍保留本节点状态并记录错误，下一连接不会立即丢失本地已接受 IP。

## 修改文件

- `common/limiter/limiter.go`
- `common/limiter/global_cache.go`
- `common/limiter/limiter_test.go`
- `docs/engineering-reports/20260818-1355-fix-global-ip-limit.md`

## 兼容性影响

- `DeviceLimit=0` 仍表示 unlimited；
- same IP 不计为新设备；
- online 回传仍使用 `UID/IP`，每次 `GetOnlineDevice` 后清空本周期 local online set；
- global unique key 仍按旧逻辑用 device limit 替换 inbound tag；
- Redis value 仍为 gocache/msgpack 编码的 `map[string]int`；
- Redis unavailable 仍 fail-open；
- API、V2Board JSON、traffic accounting、runtime tag 未改变；
- `go.mod`、`go.sum`、xray-core 未改变。

行为修正是：新 IP 在“已有数量等于 limit”时现在正确拒绝；并发 burst 不再超额或因临时全部插入而异常低于 limit。

## 正确性测试

新增覆盖：

- global same IP / new IP boundary；
- global 100 concurrent first IP、limit=5；
- local same IP / new IP、`deviceLimit=1`；
- local 100 concurrent first IP、limit=5，必须精确接受 5；
- `deviceLimit=0` 的 100 IP unlimited；
- slow global Set 不 detached；
- Redis/cache unavailable 保留 fail-open；
- cache replace/delete Close，重复 delete 不重复 Close。

定向：

```text
go test -race ./common/limiter -count=20
PASS
```

100 轮 burst stress + mutex/block profile：

```text
PASS
wall time: 0.203 s
```

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

没有通过真实 global marshaler 路径复现 plain Go map race；上述 race Gate 主要验证 shard lock、online reset、mock slow/unavailable 和 cache lifecycle 没有引入新 race。

## Benchmark before / after

### local existing IP hot path

`GOMAXPROCS=1`、`-benchmem -count=10`：

| 指标 | before 中位数 | after 中位数 | 变化 |
|---|---:|---:|---:|
| `ns/op` | 579.15 | 105.60 | -81.77% |
| `B/op` | 392 | 0 | -100% |
| `allocs/op` | 10 | 0 | -100% |

after 在 `GOMAXPROCS=8` 的中位数约：

```text
143.70 ns/op
0 B/op
0 allocs/op
```

before 的 8-thread 同参数数据未测，不能据此给并行百分比。

### local new IP at capacity（after）

`GOMAXPROCS=1`、`count=5`：

| deviceLimit | `ns/op` 中位数 | `B/op` | `allocs/op` |
|---:|---:|---:|---:|
| 1 | 185.5 | 16 | 1 |
| 5 | 257.1 | 16 | 1 |
| 100 | 1317 | 16 | 1 |

这是新 IP 的 O(device count) 精确计数路径；existing IP 不执行 Range。若真实用户常设置 100 级 DeviceLimit，应在后续用带原子 count 的 per-user state benchmark，但本阶段不扩大数据结构重写。

### global new IP at capacity（after）

local msgpack cache，`GOMAXPROCS=1`、`benchtime=200ms`、`count=3`：

| deviceLimit | `ns/op` 中位数 | `B/op` | `allocs/op` |
|---:|---:|---:|---:|
| 1 | 2304 | 824 | 17 |
| 5 | 3980 | 984 | 29 |
| 100 | 40977 | 约 12600 | 322 |

该数据明确说明 global map 每连接 msgpack decode 在大 DeviceLimit 下仍昂贵。没有正确、可比的 before global benchmark，因此不声称本阶段改善了该项；PHASE 6/连接 profile 可研究版本化 local decoded state，但必须保持跨节点/TTL 语义。

## mutex / block profile

fixture：100 轮，每轮 local 与 global 都是 100 goroutine 同一用户首次 IP burst。这是故意制造同-key 最坏竞争，不是正常连接分布。

mutex aggregate delay：

```text
sync.(*Mutex).Unlock  120.15 ms
globalLimit            98.14 ms cum
GetUserBucket          21.93 ms cum
```

block aggregate delay：

```text
sync.(*Mutex).Lock      4.75 s
globalLimit             4.19 s cum
GetUserBucket           0.56 s cum
```

aggregate goroutine wait 大于 wall time（并发累计）；测试 wall time 为 0.203 s。序列化同一用户是 DeviceLimit 精确性的必要条件；不同 key 由 64 shard 分散。后续真实 connection profile 必须确认 hash collision 和 Redis timeout 没有形成系统级热点。

## CPU / memory / goroutine / GC

- CPU proxy：见 `ns/op`；existing local 路径明显下降；
- allocation：existing local 从 `392 B/op, 10 allocs/op` 降为 0；
- heap/RSS：未测 / 无可靠数据；
- goroutine：移除每个 global 新 IP 一个 `go pushIP`，移除本层 `NewChain` setter 和 go-cache janitor；Redis client 内部资源在 replace/delete 时 Close；
- GC cycles/pause：未测 / 无可靠数据；B/op 下降预计减少 GC 输入，但未采集 GC 周期，不能量化；
- local cache retained state：lazy expiry + 每 256 writes sweep；inbound delete 时整体释放。

## build 结果

```text
go build ./...
PASS
```

## Release 状态

- Release/tag：未创建；
- `v0.9.0`：未移动；
- 阶段完成后推送 `fix/global-ip-limit`，Gate 后 fast-forward `main`。

## 已知风险

1. Redis unavailable 仍 fail-open，这是 legacy availability 选择；它不提供故障期间的严格 global enforcement。
2. 同一用户的 global miss/Set 由 mutex 串行；Redis 慢时同用户新连接会排队，context 在进入等待前创建，使排队者到锁后通常快速超时并 fail-open，避免每个请求再次完整等待，但仍需真实 Redis slow profile。
3. 64 shard 会发生不同用户 hash collision；最坏 burst profile 已记录，正常分布需 soak 验证。
4. global msgpack decode 对 limit=100 仍有高 allocation，是已测 P1，不在正确性修复中直接引入复杂 decoded-state cache。
5. limiter user 删除后的 `UserInfo`、bucket/IP cleanup 属于 PHASE 6；本阶段只在整个 inbound replace/delete 时释放 global cache。

## 未解决问题

- speed `rate.Limiter` loser allocation；
- deleted user state cleanup；
- `RateWriter` context/error；
- V2Board ETag；
- global stats scan/stale counter；
- 1C1G 与 soak。

## 下一步

PHASE 6 先建立 user churn/heap fixture，分别测 `UserInfo`、`BucketHub`、`UserOnlineIP` 的 retained state，再处理 rate limiter loser allocation 和用户删除 cleanup；不得因本阶段 existing-IP 数据好看而宣称 1C1G 目标已达到。
