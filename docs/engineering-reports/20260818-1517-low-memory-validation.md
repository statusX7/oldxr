# oldxr 低配近似连接矩阵与 15 分钟 soak 报告

## 基本信息

- 日期/时区：2026-08-18，Europe/London（UTC+1）
- 阶段：PHASE 11 / PHASE 12，1C1G 近似验证与短期 soak
- branch：`test/low-resource-soak`
- base HEAD：`103caf6f6070161291128b8f7a421adbd4331c76`
- 本报告与 fixture：由本阶段同一逻辑提交纳入
- Go：`go1.20.14 linux/amd64`
- xray-core：`github.com/xtls/xray-core v1.7.5`
- XrayR 基线：v0.9.0

## 测试环境与隔离

- Debian 12，AMD EPYC 9534，宿主机 8 vCPU / 约 15 GiB RAM。
- 临时 systemd scope：`CPUQuota=100%`、`MemoryMax=1G`。
- CPU affinity：`taskset -c 0`。
- Go runtime：`GOMAXPROCS=1`、`GOMEMLIMIT=768MiB`。
- 测试进程 soft `ulimit -n`：1024；fixture 不创建真实 socket，实测 `fd=7`，因此未提高限制。
- cgroup 实际值：`memory.max=1073741824`，`cpu.max=100000 100000`。
- pprof：本阶段未采集；此前 dispatcher allocation profile 已记录在 `20260818-1440-perf-dispatcher.md`。
- mutex/block profile：未测 / 无可靠数据。本阶段未修改同步机制，race 回归用于并发验证。

## 问题背景

生产目标是尽可能让 oldxr 在 1 vCPU / 1 GiB 节点上稳定承载百人级活跃用户。此前只有 microbenchmark，没有可重复的连接数量矩阵和资源趋势 fixture，无法区分 active users、connection count、connection churn 与 retained state。

本阶段新增显式 `soak` build tag 下的 synthetic fixture，不进入普通 `go test ./...`：

- `app/mydispatcher/connection_soak_test.go:31-45` 采样 heap、RSS、allocation、GC、goroutine 与 fd；
- `app/mydispatcher/connection_soak_test.go:107-149` 构造 100 用户 dispatcher、limiter、stats 与 rule 状态；
- `app/mydispatcher/connection_soak_test.go:225-268` 执行 100/500/2000 connection 矩阵；
- `app/mydispatcher/connection_soak_test.go:270-323` 保持 500 个 long-lived synthetic links，并持续建立/关闭短连接。

## Fixture 定义与边界

`features=false` 关闭 user stats、speed limit、device limit 与 rule detect；`features=true` 同时启用：

- uplink/downlink user stats wrapper；
- 每用户 speed limiter；
- local DeviceLimit；
- 一条已编译 rule 的 detect。

soak 固定为：

```text
100 active users
× 5 long-lived synthetic connections/user
= 500 retained link pairs

每 10 ms 建立并关闭 10 个 short-lived link pairs
≈ 1,000 churn connections/s
```

这里的 connection 是 `DefaultDispatcher.getLink` 创建的 xray `transport.Link`/pipe 组合，不是完整 VMess/Trojan/Shadowsocks 握手，不创建真实 TCP socket，不经过真实 panel、TLS、kernel network stack 或 payload forwarding。因此结果是 `synthetic / approximate`，不能宣称等同生产吞吐或百名真实用户。

## 100 用户 connection 矩阵

命令：

```bash
systemd-run --wait --collect --pipe \
  --working-directory=/root/projects/oldxr \
  -p CPUQuota=100% -p MemoryMax=1G \
  /usr/bin/env GOMAXPROCS=1 GOMEMLIMIT=768MiB \
  /usr/bin/taskset -c 0 \
  go test -tags=soak ./app/mydispatcher \
  -run '^TestSyntheticConnectionMatrix$' -count=1 -v
```

| 连接数 | 每用户连接 | features | setup/connection | live heap | live heap objects | live RSS | cleanup heap | goroutine | fd |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 1 | off | 2.127 µs | 1,091,488 B | 9,042 | 24,313,856 B | 826,840 B | 3 | 7 |
| 100 | 1 | on | 3.889 µs | 1,184,904 B | 10,297 | 24,399,872 B | 827,272 B | 3 | 7 |
| 500 | 5 | off | 2.117 µs | 1,581,024 B | 21,134 | 24,829,952 B | 827,480 B | 3 | 7 |
| 500 | 5 | on | 3.760 µs | 1,886,088 B | 25,591 | 24,719,360 B | 827,784 B | 3 | 7 |
| 2,000 | 20 | off | 2.004 µs | 3,552,384 B | 66,022 | 25,481,216 B | 827,864 B | 3 | 7 |
| 2,000 | 20 | on | 5.239 µs | 4,464,120 B | 73,114 | 26,517,504 B | 828,264 B | 3 | 7 |

观察：

- 2,000 connection 的 feature-on 场景相对 feature-off 增加约 0.87 MiB live heap；该差异同时包含 stats、speed/device limiter 和 rule，不能归因于单一组件。
- 所有场景完成 close、limiter cleanup、GC 后，heap 均回落到约 0.79 MiB。
- 此矩阵单次样本用于容量边界观察，不是 `count=10` 的稳定 microbenchmark；`ns/op`、`B/op`、`allocs/op` 的稳定结果应以 dispatcher/limiter 专项报告为准。

## 15 分钟 soak 结果

命令同上，增加：

```text
OLDXR_SOAK_DURATION=15m
OLDXR_SOAK_SAMPLE_INTERVAL=1m
```

结果：

- 完成：899,810 次 short-lived connection churn；
- retained：500 个 long-lived synthetic connections；
- cgroup 总 CPU：19.297 s，包含 `go test` 编译与启动；不能作为纯运行时 CPU 的精确值；
- cgroup memory peak：187,617,280 B（约 178.9 MiB），包含 Go 编译器及测试启动过程；
- 测试进程 steady RSS：第 3–14 分钟主要稳定在约 34 MiB；
- soak sampled live heap：约 1.7–3.9 MiB 周期波动，没有随累计 churn 单调增长；
- 结束清理后 heap：824,856 B；
- 结束清理后 RSS：32,763,904 B（约 31.25 MiB）；
- 结束时 heap objects：3,951；
- 总分配：1,142,635,600 B；包含启动、500 个 retained links 和全部 churn，粗略约 1.27 KiB/churn，不等于严格 `B/op`；
- mallocs/frees：28,827,736 / 28,823,785，最终差 3,951，与结束 heap object 数一致；
- GC cycles：480；
- GC pause total：16,642,078 ns（约 16.64 ms）；
- goroutine：绝大多数采样为 2，一次采样为 3，结束为 2；
- fd：所有采样均为 7；
- 500 个 retained links 的关闭、limiter cleanup、GC 与 `FreeOSMemory`：2.143 ms。

这些数据没有显示历史 connection churn 导致 live heap、goroutine 或 fd 单调增长。它不能排除真实协议、socket、TLS、panel、Redis 或 xray routing 路径中的泄漏。

## 修改方案与文件

本阶段仅新增测试基础设施：

- `app/mydispatcher/connection_soak_test.go`
- `docs/engineering-reports/20260818-1517-low-memory-validation.md`

生产源码修改：0。

## 正确性、race 与工程验证

- `go test -tags=soak ./app/mydispatcher -run '^TestSyntheticConnectionMatrix$' -count=1`：通过。
- 1 分钟 pilot soak：通过，59,980 churn，清理后 heap 825,944 B。
- 15 分钟 formal soak：通过，899,810 churn。
- `go test -race -tags=soak ./app/mydispatcher -run '^TestSyntheticConnectionMatrix$' -count=10`：通过（修正 feature 开关前已通过；最终 fixture 在提交前再次验证）。
- `go test ./...`：通过。
- `go vet ./...`：通过。
- `go vet -tags=soak ./app/mydispatcher`：通过。
- `go test -race ./...`：sandbox 内首次仅因 `httptest` 无 loopback socket 权限失败；允许 loopback 后同命令通过。
- `CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' ./main`：通过，输出位于 `/tmp`，未纳入仓库。

## Benchmark before / after

本阶段没有生产性能修改，因此不存在 before/after。连接 setup 数据是容量 fixture 的单次 timing，不作为优化收益声明。

- `ns/op`：不适用；
- `B/op`：不适用；
- `allocs/op`：不适用；
- CPU before/after：不适用；
- heap/RSS before/after：使用同一测试内的 before/live/cleanup 样本，见上表；
- mutex/block：未测 / 无可靠数据。

## V2Board 1.6.0 兼容性影响

无生产行为变化。fixture 使用 synthetic user/tag，不修改 V2Board route、JSON 字段、ETag、traffic accounting、认证身份或 runtime tag 语义。

## Build / Release 状态

- Linux amd64 build：通过。
- Linux arm64 cross-build：本阶段未测，留给 Release Gate。
- Release：未创建；本阶段不包含发布路径修改。

## 已知风险与未解决问题

- 未产生真实 TCP connection，无法测量 kernel socket memory、fd 扩展、真实 goroutine-per-connection、TLS buffer 或网络 throughput。
- 未执行独立 30 分钟/1 小时 run；15 分钟内的 steady trend 已记录，但更长时间和真实协议 soak 仍需后续验证。
- cgroup memory peak 包含 compiler，因此不能当作 oldxr daemon RSS。
- `debug.FreeOSMemory` 只用于验证 cleanup 后可回收性，不代表生产运行时会主动归还相同 RSS。
- 真实 1C1G 节点的 CPU%、RSS、连接延迟与 throughput 仍需要隔离 VM/容器加协议客户端和 mock V2Board panel 验证。

## 下一步

1. 完成 self-contained Release chain，并在 Linux amd64/arm64 archive 上验证内容和 checksum。
2. 使用 mock panel + 至少一种真实协议执行 socket-level 1C1G fixture，合理提高该测试子进程的 `ulimit -n`。
3. 在 Release candidate 上执行更长 soak，并区分 idle long-lived、short churn 与 payload throughput。
