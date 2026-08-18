# oldxr 第二阶段最终工程总结

## A. Git

### Release source

```text
main:         b91d3c3ff567d40d4c02200d26dd26965909640b
master:       b91d3c3ff567d40d4c02200d26dd26965909640b
v0.9.0-r1:    b91d3c3ff567d40d4c02200d26dd26965909640b
v0.9.0:       23feaddb273c7c6d737f41ccab5e5375f4a63ede
```

`main`、`master` 与 release tag 在发布时完全一致。最终两个报告会形成一个 post-release docs-only commit，并 fast-forward 到 `main/master`；`v0.9.0-r1` 不移动，确保 Release binary 与 tag source 一致。最终 docs commit SHA 以 Git history 和任务最终回复为准。

第二阶段主要 commits：

```text
92f9146  chore: add oldxr engineering baseline
585f70e  test: restore deterministic validation baseline
8ae8eaa  fix: preserve concurrent traffic increments
dd998eb  fix: replace changed runtime users safely
ef4ecaf  fix: synchronize controller shared state
84d9900  fix: serialize global device limit updates
c4bdbac  perf: clean up limiter state and allocations
46ace5a  perf: add V2Board conditional user sync
871441f  perf: index traffic counters by controller tag
f49d969  test: benchmark dispatcher connection setup
103caf6  fix: make rule updates safe and deterministic
6eecd74  test: add low-resource connection soak coverage
b91d3c3  fix: make oldxr release chain self-contained
e7d351d  ci: use Node 24 GitHub Actions
754cdf6  fix: set repository for release uploads
a35eee0  fix: make release archives timezone independent
```

所有工作分支和阶段 main 均使用普通 fast-forward/push；force push、history rewrite、automatic merge：0。

## B. 版本

```text
XrayR compatibility baseline: v0.9.0
maintenance release:          v0.9.0-r1
V2Board target:               1.6.0 legacy API
Go:                           1.20.14
xray-core:                     v1.7.5
CGO:                           disabled for Release
module identity:               github.com/XrayR-project/XrayR
```

没有升级 XrayR、xray-core 或项目 dependency，没有修改 `go.mod/go.sum`。

## C. P0 修复

### Traffic accounting

旧链路 `Value → HTTP report → Set(0)` 会覆盖 Value 后到 Set 前的并发增量。新实现使用 atomic drain，report 失败恢复 pending bytes；deterministic tests 覆盖成功、失败、连续多轮、并发增量、restart/reset 与 total bytes conservation。

counter cycle microbenchmark：

```text
before median: 5.996 ns/op, 0 B/op, 0 allocs/op
after median:  5.397 ns/op, 0 B/op, 0 allocs/op
latency:       about -10.0%
```

### Same UID modified user

同 UID 的 UUID/password/email/protocol identity 变化现在产生 delete-old/add-new；SpeedLimit/DeviceLimit 变化也可靠更新 limiter/runtime 状态。50k user、0% churn：

```text
before: 73.61 ms/op, 37.95 MB/op, 201,669 allocs/op
after:  11.64 ms/op,  2.21 MB/op,   1,693 allocs/op
```

50k/1% churn latency约 -85.6%，B/op 约 -93.2%，allocs/op 约 -99.2%。这是 pure diff benchmark，不包含 core mutation 或 panel HTTP。

### Controller shared state

`nodeInfo`、`Tag`、`userList`、`clientInfo` 改为同步发布和 immutable snapshot；HTTP/core/connection close 不在长临界区内。修复前定向 fixture 可被 race detector 定位，修复后 stress/race 通过。snapshot read：

```text
single:   median about 20.16 ns/op, 0 B/op, 0 allocs/op
parallel: median about 47.24 ns/op, 0 B/op, 0 allocs/op
```

### DeviceLimit / Global IP

修复 limit boundary、parallel first-IP lost update、异步 Redis task amplification 与 cache lifecycle。未把未复现的 plain-map race 冒充已确认问题。

local existing IP：

```text
before: 579.15 ns/op, 392 B/op, 10 allocs/op
after:  105.60 ns/op,   0 B/op,  0 allocs/op
```

## D. CPU 优化

### Limiter speed path

避免 rate limiter loser allocation，并增加 user deletion cleanup：

```text
before: 214.45 ns/op, 96 B/op, 2 allocs/op
after:  132.45 ns/op,  0 B/op, 0 allocs/op
```

19,000 historical UID churn 后 retained entries 只等于 active users。

### V2Board ETag / 304

首次 full 200 后保存 controller-local ETag，后续发送 `If-None-Match`；304 不 decode/diff user body。unchanged V2ray：

| users | before | after | before B/op | after B/op | before allocs | after allocs |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1k | 2.445 ms | 17.36 µs | 1.858 MB | 5.6 KB | 16,109 | 66 |
| 10k | 26.21 ms | 49.12 µs | 21.81 MB | 17.9 KB | 160,134 | 67 |
| 50k | 156.28 ms | 47.15 µs | 105.64 MB | 17.9 KB | 800,150 | 67 |

full 200 仍执行相同 legacy decode，不声称该路径更快。

### Stats index

从每个 Controller 扫描 global counters 改为 per-tag index：

```text
50k counters / 100 controllers / 90% stale
before: 1.475 s/op, 321.15 MB/op, 5,006,975 allocs/op
after:  6.412 ms/op, 1.142 MB/op, about 6,834 allocs/op
```

parallel counter lookup：

```text
before: 69.76 ns/op, 64 B/op, 1 alloc/op
after:  33.18 ns/op,  0 B/op, 0 alloc/op
```

### Rule detect

`Pattern.Match([]byte(destination)) → MatchString`：24 B/1 alloc → 0 B/0 alloc；UID parse `strings.Split → LastIndexByte`：105.7 ns/80 B/1 alloc → 5.52 ns/0/0。

## E. 内存优化

已证明的 allocation 降低集中在 user diff、ETag 304、stats index、DeviceLimit existing-IP、speed limiter 和 rule detect，详见上文。

dispatcher full-feature 当前 baseline 仍约：

```text
1,588–1,745 ns/op
1,112 B/op
28 allocs/op
```

profile 指向 xray pipe/channel 与 wrapper 创建；本阶段没有在缺少安全证据时重写 xray-core connection primitives。

1C1G synthetic soak 结束清理：

```text
heap:         824,856 B
heap objects: 3,951
RSS:          32,763,904 B
goroutines:   2
fd:           7
```

没有可靠的生产整进程 before RSS，因此不声称全 daemon RSS 降低百分比。

## F. GC

15 分钟 synthetic soak：

```text
899,810 churn connections
GC cycles:        480
GC pause total:   16.642 ms
total allocation: 1,142,635,600 B
```

live heap 在约 1.7–3.9 MiB 周期波动，未随累计 churn 单调增长。由于没有相同 workload 的原始代码 before soak，本报告只陈述 after trend；B/op 下降说明 GC input 下降，但不编造整机 GC before/after。

## G. Concurrency

- 全仓库 `go test -race ./...`：通过；
- traffic、user diff、Controller、DeviceLimit、limiter、ETag、stats/rule 有定向 race count/stress；
- Controller 不持 state lock 执行 HTTP/core/connection close；
- global DeviceLimit 不再为每个新 IP 无界启动 goroutine；
- rule slice 发布前复制，避免 backing array 被复用写；
- limiter user deletion/churn state cleanup 受测试保护。

mutex/block profile：只有相关阶段做了定向观察，没有统一可比较数值，未测 / 无可靠汇总数据。

## H. 100-user / connection test

在 100 users 下测 1/5/20 connections per user，features on 包含 stats、speed/device limiter 与 rule：

| connections | setup/connection | live heap | live RSS | cleanup heap |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 3.889 µs | 1,184,904 B | 24,399,872 B | 827,272 B |
| 500 | 3.760 µs | 1,886,088 B | 24,719,360 B | 827,784 B |
| 2,000 | 5.239 µs | 4,464,120 B | 26,517,504 B | 828,264 B |

这是 `DefaultDispatcher.getLink`/pipe synthetic fixture，不是 TCP/TLS/protocol handshake。

## I. 1C1G approximate result

约束：

```text
systemd cgroup MemoryMax=1G
CPUQuota=100%
taskset -c 0
GOMAXPROCS=1
GOMEMLIMIT=768MiB
```

负载：100 users × 5 retained links + 约 1,000 short-lived churn/s，15 分钟完成 899,810 churn。

- 测试进程 steady RSS 主要约 34 MiB；
- cgroup peak 约 178.9 MiB，但包含 Go compiler，不是 daemon RSS；
- cgroup CPU 19.297 s，同样包含 compile/startup；
- goroutine 与 fd 无增长斜率；
- cleanup 约 2.143 ms。

结论仅为 `synthetic / approximate`。没有真实 TCP socket、VMess/Trojan/Shadowsocks、TLS、payload throughput、panel 或 Redis，不能宣称已达到生产“1C1G 百人”目标。

## J. V2Board 1.6.0 compatibility

通过 deterministic fixture 验证：

- legacy config/user/submit routes；
- `node_id`、`token`、top-level `data`；
- VMess `uuid/email/alter_id`；
- Trojan `password`；
- Shadowsocks `port/cipher/secret`；
- traffic `user_id/u/d`；
- `inbounds` 与 legacy `inbound`；
- stream network/security、`local_port`、`ssl.sni`；
- ETag first 200、304、changed ETag、invalid/error isolation；
- VMess/Trojan/Shadowsocks 304；
- HTTP 400 error；
- legacy no-op status semantics 未改。

没有真实 V2Board credential 或 production panel smoke test。

## K. Install / Release

```text
Release tag: v0.9.0-r1
Release URL: https://github.com/statusX7/oldxr/releases/tag/v0.9.0-r1
amd64 SHA256: 52611697f4143c031a97690a3481abe06e066db827e02c93a32b8332dc20d600
arm64 SHA256: 94100aaad09169b97abe1b4d5cd5096377d714b3fcf5b36cda9043f232a48776
```

fresh install、update、`XrayR.sh update`、`update_shell`、checksum failure、archive layout、binary version、public systemd transient lifecycle 均通过。线上两个主 asset 的 sidecar 校验均为 `OK`。

tag workflow 实际运行发现旧 action majors 的 Node.js 20 deprecation 警告；最终 main/master 已切换到官方 Node.js 24 majors并通过 `actionlint`，不移动已发布 tag。远程 validate 和 24 个 cross-build jobs 全部成功；upload job 的 `GH_REPO` 缺失已修复，24 组 artifacts 的 sidecar 全部验证后受控补传，Release 共 48 个 assets。

Node.js 24 workflow maintenance 后的 CodeQL run `32152320703` 已完成且结论为 `success`。

本地与 GitHub runner 的 binary hash一致，但 ZIP metadata 曾受 timezone 影响；最终 main/master 已固定 `TZ=UTC`，并以 London/UTC 两次 byte-for-byte build 证明修复。

Docker run `32150623172` 从 release tag 成功构建并推送 `linux/amd64`、`linux/arm64`、`linux/arm/v7`，tags 为 `v0.9.0-r1`、`0.9.0`、`latest`，manifest digest 为 `sha256:3566a893a0bfbf49307cc62ff0e411d47ff20f50c9a292e884dd7987f79365ff`。公开 GHCR package 页面匿名 HTTP 访问为 200；本机无 Docker/Podman，因此未执行 pull/run smoke test。

## L. 用户最终安装命令

```bash
bash <(curl -Ls https://raw.githubusercontent.com/statusX7/oldxr/master/install.sh) 0.9.0
```

实际解析：

```text
0.9.0 → v0.9.0-r1
```

日志明确显示 actual tag、repository、architecture asset、checksum 和 binary version；不存在 `statusX7/XR` fallback。

## M. 未解决问题

### P0

当前阶段已知清单中没有未修复 P0；这不是对所有未知缺陷不存在的保证。

### P1

1. Controller runtime reload 仍缺少完整 transactional rollback；new runtime build 失败可能影响可用状态，需要独立设计和 fault-injection。
2. global Redis DeviceLimit 仍需每连接读取/解码 state，大 DeviceLimit 下成本明显；不能破坏跨节点 TTL/consistency 语义。
3. stale xray stats counter 的安全回收仍受 long-lived connection late bytes 约束；直接删除会漏计费。
4. dispatcher full-feature 仍约 1.1 KiB/28 allocs per synthetic connection，主要属于 xray pipe/writer primitives；需要真实 connection profile 决定是否可优化。
5. 缺少真实协议/TLS/socket/V2Board mock 的 1C1G 和 30–60 分钟以上 soak。

### P2

1. arbitrary regexp rule detect 仍是 O(rule count)。
2. `GetDetectResult.LoadAndDelete` 与 concurrent new detection 的跨 report window 归属需要语义审计。
3. Docker/非 amd64 target 需要真实目标 runtime 测试。
4. geodata 现在可重复但不会自动 latest；必须建立受审查的显式更新流程。

## N. 下一阶段建议

1. 用 mock V2Board 1.6.0 + real xray inbound/client 建立 socket/TLS protocol fixture，分别测 active users、connections/user、throughput 与 churn。
2. 在独立 VM/cgroup 执行 30 分钟与 1 小时 real-protocol soak，采集 CPU profile、heap/allocs、goroutine、mutex/block、RSS、fd 与 GC slope。
3. 先为 Controller reload 建立 fault-injection rollback test，再实施最小 transactional reload。
4. 对 Redis/global DeviceLimit 做 latency/command-rate/profile，只有证据充分时研究 local versioned cache。
5. 为 stats counter cleanup 引入 connection-lifetime reference 之前，先证明 late bytes 不丢失。

## 工程文档

- Release 报告：`docs/engineering-reports/20260818-1545-release-v0.9.0-r1.md`
- 本总结：`docs/engineering-reports/20260818-1545-phase2-final-summary.md`
- 所有阶段证据：`docs/engineering-reports/`
