# PHASE 7：V2Board 1.6.0 ETag / 304 条件用户同步

## 基本信息

- 日期/时区：2026-08-18 14:15 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 7 / legacy V2Board ETag
- branch：`perf/v2board-etag`
- 修改前 HEAD：`c4bdbac`（`main`）
- 本报告对应 commit：提交后以 Git 历史为准
- Go version：`go1.20.14 linux/amd64`
- xray-core：`v1.7.5`，未升级
- 测试环境：Debian 12、AMD EPYC 9534、8 vCPU、约 15 GiB RAM、linux/amd64

## V2Board 1.6.0 一手证据

正式参考源码：`/root/projects/reference/v2board-1.6.0`，对应公开 tag/branch 1.6.0。

以下 controller 的 `user()` 都采用同一顺序：

1. 验证 server；
2. 更新 `SERVER_*_LAST_CHECK_AT`；
3. 生成完整用户 result；
4. `sha1(json_encode($result))`；
5. 检查 request `If-None-Match` 是否包含 hash；
6. 命中则 `abort(304)`；
7. 200 response 返回带双引号的 `ETag: "<sha1>"`。

证据位置：

- `app/Http/Controllers/Server/DeepbworkController.php::user()`，约 44–65 行；
- `app/Http/Controllers/Server/TrojanTidalabController.php::user()`，约 44–62 行；
- `app/Http/Controllers/Server/ShadowsocksTidalabController.php::user()`，约 39–57 行。

因此发送 conditional request 不会跳过 `LAST_CHECK_AT`；304 是 V2Board 1.6.0 明确定义的兼容行为，不是从新版 adapter 猜测。

`LAST_PUSH_AT` 仍只在 traffic `submit()` 更新，本阶段没有改变 traffic report。

## 问题背景

legacy `api/v2board.APIClient.GetUserList()` 原来忽略 response ETag，所有 polling 都执行：

```text
HTTP body transfer
simplejson decode
per-user field extraction
[]api.UserInfo allocation
controller diff
GC
```

对 unchanged 50k 用户，修改前 benchmark 单轮约 156 ms、105.6 MB allocation、800k allocations。

Shadowsocks 还有额外问题：`GetNodeInfo -> ParseSSNodeResponse -> GetUserList`，随后 controller Start/monitor 又调用一次 `GetUserList`，同一轮请求两次相同 user endpoint。直接加入 ETag 会让第二次返回 304，并导致首次 Start 把 `users no change` 当错误，因此必须显式处理这一 legacy coupling。

## 修改方案

### 通用 conditional user fetch

- 每个 `APIClient` 实例保存自己的 `userETag` 和 `lastUserList`；
- 第一次没有 ETag，强制完整 200；
- 有 ETag 后发送原样 `If-None-Match`，包括 V2Board 返回的双引号；
- 304 且已有 cache 时返回 legacy sentinel error text `users no change`；
- 304 但没有任何 full baseline 时返回明确错误，不伪装 unchanged；
- 200 body 解析完全成功后才更新 ETag/cache；
- invalid JSON、HTTP/network error 不更新 ETag；
- 200 response 不再提供 ETag 时清空旧 ETag，下一轮重新 full fetch；
- ETag/用户 cache 是 per client，不在 controller、node 或 panel 间共享。

### Shadowsocks 单次 fetch

- `GetNodeInfo` 通过 conditional user fetch 推导 port/cipher；
- 将本次 fetch 结果保存为一次性 `ssPending`；
- controller 紧接着的 `GetUserList` 消费 pending，不再发第二个 HTTP；
- full 200 pending 返回完整 users；
- 304 pending 返回 `users no change`；
- 304 时 node info 使用 last full users 推导，面板重启/ETag changed 后仍走 full 200；
- public `ParseSSNodeResponse` 仍可独立 fetch 并从 cached/full users 构建 node info。

## 修改文件

- `api/v2board/v2board.go`
- `api/v2board/v2board_test.go`
- `api/v2board/v2board_benchmark_test.go`
- `docs/engineering-reports/20260818-1415-perf-v2board-etag.md`

## 兼容性影响

- API paths 不变：Deepbwork/TrojanTidalab/ShadowsocksTidalab；
- `node_id`、`token`、`local_port` query 不变；
- VMess `uuid/email/alter_id`、Trojan `password`、SS `port/cipher/secret` 不变；
- SpeedLimit/DeviceLimit mapping 不变；
- controller 仍通过 error text `users no change` 进入 no-diff 路径；
- `LAST_CHECK_AT` 在 V2Board 端仍会对 304 更新；
- `LAST_PUSH_AT`、traffic/online legacy no-op 不变；
- Go module、xray-core、dependencies 未改变。

## 正确性测试

覆盖：

- V2ray 第一次 200 + 第二次 `If-None-Match`/304；
- Trojan 第一次 200 + 304；
- Shadowsocks first config/user 共用一次 HTTP，下一轮 304 仍能构建 node；
- ETag v1 -> 304 -> v2 full -> invalid v3 -> 保持 v2 -> valid v3 recovery；
- invalid response 不污染 ETag；
- 第二个 client 第一次 request 不携带第一个 client ETag；
- legacy user fields、node fields、rules、traffic fixture 原有断言继续通过。

定向：

```text
go test -race ./api/v2board -count=20
PASS
```

## Benchmark 方法

- custom `http.RoundTripper`，无 loopback/socket 噪音；
- body 在 timer 外生成；
- prime full 200 在 timer 外执行；
- conditional benchmark timer 内全部为 304；
- `GOMAXPROCS=1`、`benchtime=3x`、`count=3`；
- before 是相同 conditional transport，但旧 client 不发送 header，因此每轮仍得到 full 200。

## Benchmark before / after：V2ray unchanged sync

| users | before `ns/op` 中位数 | after `ns/op` 中位数 | before `B/op` | after `B/op` | before allocs/op | after allocs/op |
|---:|---:|---:|---:|---:|---:|---:|
| 1k | 2,444,519 | 17,359 | 1,857,602 | 5,581 | 16,109 | 66 |
| 10k | 26,214,017 | 49,117 | 21,808,869 | 17,930 | 160,134 | 67 |
| 50k | 156,275,670 | 47,154 | 105,643,237 | 17,930 | 800,150 | 67 |

粗略变化：

- 1k latency -99.29%，allocation bytes -99.70%；
- 10k latency -99.81%，allocation bytes -99.92%；
- 50k latency -99.97%，allocation bytes -99.98%。

304 path 不随用户 body 线性增长；10k/50k B/op 都约 17.9 KB，主要是 Resty request/response 对象，不是 user slice。

## Protocol 304 矩阵

对 V2ray/Trojan/Shadowsocks 的 1k/10k/50k 全部执行 304 benchmark。由于 `count=3` 且单次仅数十微秒，噪音明显，记录范围而不伪造精确排序：

```text
V2ray:       12.9–52.7 µs/op, 5.5–17.9 KB/op, 66–67 allocs/op
Trojan:      11.0–45.9 µs/op, 5.5–17.9 KB/op, 66–67 allocs/op
Shadowsocks: 14.9–73.7 µs/op, 5.6–17.9 KB/op, 66–67 allocs/op
```

三种协议的 304 path 都不 decode body；差异属于 microbenchmark/request-object 噪音。

## Full 200 path

修改后 full 200 仍进行相同 legacy decode。allocation 与 before 接近：

```text
1k:  约 1.858 MB / 16,113 allocs
10k: 约 21.80 MB / 160,135–160,137 allocs
50k: 约 105.64 MB / 800,152–800,153 allocs
```

短 `count=3` 时间数据有明显 GC 噪音；新增锁/cache 写入相对于 JSON decode 很小，但本报告不声称 full 200 更快。主要收益严格限定为 unchanged 304。

## CPU / memory / GC

- CPU proxy：unchanged `ns/op` 如上；
- B/op/allocs：大用户量下降两个到四个数量级；
- heap/RSS：未测 / 无可靠 service-level 数据；
- GC cycles/pause：未单独采集；B/op 大幅下降意味着减少 GC 输入，但未量化 pause；
- retained memory：每 controller 保留最后一个完整 user slice，controller 本来已保留相同 `userList`；adapter 新增一个 slice pointer 引用同一 parsed slice，不复制 50k users；
- goroutine：未新增 background goroutine。

## go test / vet / race / build

```text
go test ./...       PASS
go vet ./...        PASS
go test -race ./... PASS
go build ./...      PASS
```

## Release 状态

- Release/tag：未创建；
- `v0.9.0`：未移动；
- 完成 Gate 后推送 `perf/v2board-etag` 并 fast-forward `main`。

## 已知风险

1. V2Board 服务端仍会在计算 ETag 前读取并构造完整用户 result；本优化降低 oldxr 网络/JSON/GC，不消除 panel 端数据库/array/hash 成本。
2. adapter 与 controller 同时引用 last full user slice；它们只读使用。未来若引入原地修改必须先复制或重新定义 ownership。
3. 304 error 仍依赖 legacy text `users no change`；这是现有 controller contract，本阶段不扩大 API interface。
4. Resty 304 path 仍约 66–67 allocations；若 profile 证明 polling 仍是 CPU hotspot，可继续研究 request reuse，但不能共享可变 request。

## 未解决问题

- stats global scan / stale counters；
- dispatcher counter/tag construction；
- RuleManager correctness/P2；
- 1C1G service-level GC/RSS；
- release/install chain。

## 下一步

进入 PHASE 8，先以 1k/10k/50k counters、1/10/100 controllers 和 stale ratio 建立 counter visit benchmark，再决定 per-tag index 或 cleanup；不得因 ETag 数据巨大就跳过 traffic semantics 验证。
