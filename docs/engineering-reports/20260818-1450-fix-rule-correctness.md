# PHASE 10：RuleManager 正确性、并发快照与热路径优化

## 基本信息

- 日期/时区：2026-08-18 14:50 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 10 / rule correctness 与 measured P2
- branch：`fix/rule-correctness`
- 修改前 HEAD：`f49d969`（`main`）
- 本报告对应 commit：提交后以 Git 历史为准
- Go version：`go1.20.14 linux/amd64`
- xray-core：`v1.7.5`，未升级
- 测试环境：Debian 12、AMD EPYC 9534、8 vCPU、约 15 GiB RAM、linux/amd64

## 已确认问题

### 1. 空规则不能清除旧规则

`common/rule.Manager.UpdateRule` 本身可以保存 empty slice，但 Controller 在 Start 和 monitor 都只在 `len(ruleList) > 0` 时调用它。因此 panel 从非空规则更新为空时，旧规则继续拒绝连接。

### 2. 已发布 slice backing array ownership 不明确

多个 adapter 使用：

```text
ruleList := c.LocalRuleList
ruleList = append(ruleList, remoteRules...)
```

如果 `LocalRuleList` 尚有 capacity，append 会复用 backing array。返回 slice 被 `RuleManager` 直接保存后，下一轮 adapter append 可能覆盖同一个 backing array；connection `Detect` 同时读取时会形成 race 或不一致快照。

### 3. invalid regexp panic

V2Board、V2RaySocks、PMpanel、ProxyPanel、SSPanel、newV2Board 的本地/远端规则使用 `regexp.MustCompile`。panel 或本地文件出现 `[` 等非法表达式会 panic，而不是保留旧规则或跳过错误行。

### 4. HTTP 400 被当成成功

以下 legacy adapter 的 `parseResponse` 使用 `StatusCode() > 400`：

- V2Board；
- V2RaySocks；
- PMpanel；
- ProxyPanel；
- SSPanel。

因此正好 400 的 response 会继续进入 JSON/result 解析，甚至可能被当成成功数据。

### 5. rule match / UID parse allocation

每条待匹配规则执行：

```text
Pattern.Match([]byte(destination))
```

命中后通过 `strings.Split(email, "|")` 取得最后 UID。Benchmark 证明两处均产生可消除的 per-detection allocation。

## 修改方案

### 不可变规则快照

- `Manager.UpdateRule` 对非空 input 先比较 ID 与 regexp string；
- 发布前复制 `[]api.DetectRule`，不再读取调用方 backing array；
- empty update 直接 `Delete(tag)`；
- Controller 对成功获取的 empty rule list 也调用 `UpdateRule`；
- `Detect` 跳过 nil pattern，避免非 adapter 调用方构造无效值时 panic。

### 安全 regexp 编译

在一级兼容模型 `api` 中新增 `CompileDetectRule`：

- valid pattern 返回 compiled `DetectRule`；
- invalid pattern 返回 error，不 panic；
- remote invalid rule 使该轮 `GetNodeRule` 返回 error，Controller 保留旧 snapshot；
- local invalid line 记录中文日志并跳过，其余有效规则仍加载；
- adapter 每次以复制后的 `LocalRuleList` 为起点，避免自身返回 slice 复用；
- 顺带修复 `newV2Board.readLocalRuleList` 在 `os.Open` error 检查前 `defer file.Close()` 的 nil pointer panic。

### HTTP status

五个 legacy adapter 改为：

```text
StatusCode() >= http.StatusBadRequest
```

newV2Board 原有 `> 399` 已正确覆盖 400，没有改变。

### measured hot path

- `Regexp.Match([]byte(destination))` 改为 `Regexp.MatchString(destination)`；
- UID 使用 `strings.LastIndexByte(email, '|')` 后解析最后 segment；
- email 中间包含 `|` 的 legacy 行为仍取最后 UID；
- malformed email 仍拒绝命中的 destination，但不产生错误 detect result。

## 修改文件

生产代码：

- `api/apimodel.go`
- `api/newV2board/v2board.go`
- `api/pmpanel/pmpanel.go`
- `api/proxypanel/proxypanel.go`
- `api/sspanel/sspanel.go`
- `api/v2board/v2board.go`
- `api/v2raysocks/v2raysocks.go`
- `common/rule/rule.go`
- `service/controller/controller.go`

测试/Benchmark：

- `api/apimodel_test.go`
- 各 legacy adapter `response_test.go`
- `api/newV2board/rule_test.go`
- `api/v2board/v2board_test.go`
- `common/rule/rule_test.go`
- 本报告。

## 正确性测试

覆盖：

- valid/invalid `CompileDetectRule`；
- V2Board remote invalid regexp 返回 error 而不 panic；
- V2Board local invalid line 被跳过、valid line 保留；
- newV2Board missing local file 不再 nil pointer panic；
- 五个 legacy adapter 的 HTTP 400 全部返回 error；
- non-empty -> empty 后旧 rule 不再命中，空 entry 不保留；
- caller 修改原 slice 后 published rule 不变；
- caller slice mutation 与 Detect 并发，无 race 且 snapshot 稳定；
- rule publication 与两个 Detect reader 并发；
- nil pattern 不 panic；
- malformed email 不产生 detect result；
- email 中含多个 `|` 时最后 UID `42` 正确记录。

定向 race：

```text
go test -race ./common/rule -run 'Test(Detect|UpdateRule)' -count=20
PASS

go test -race ./api/v2board -count=20
PASS
```

## Benchmark before / after

### regexp match

`GOMAXPROCS=1`、同一 binary 直接比较：

```text
Match([]byte): 24 B/op, 1 alloc/op
MatchString:    0 B/op, 0 alloc/op
```

两组重复样本中 latency 中位数从约 346–458 ns 降到约 303–334 ns，观测改善约 12%–27%。时间受短 benchmark/CPU 状态影响，因此只把 allocation 归零视为稳定结论。

### UID parse on rejected destination

`GOMAXPROCS=1`、`benchtime=200ms`、`count=5`：

| 方法 | 中位数 ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `strings.Split` | 105.7 | 80 | 1 |
| `LastIndexByte` | 5.52 | 0 | 0 |

latency 约 -94.8%，并消除一次 80-byte allocation。该收益只发生在 rule 已命中并需要解析 UID 的路径。

### production Manager.Detect after

最后一条规则命中、RuleID=-1（排除 result set 写入）：

| rules | 中位数 ns/op | B/op | allocs/op |
|---:|---:|---:|---:|
| 1 | 约 110 | 0 | 0 |
| 10 | 约 421 | 0 | 0 |
| 100 | 约 4,245 | 0 | 0 |

复杂度仍是 O(rule count)。本阶段不引入 trie/automaton/cache，因为 rule 是任意 regexp，改变执行模型会增加兼容和维护风险。

## CPU / allocation profile

100 rules、3 s profile：

```text
3,665 ns/op
0 B/op
0 allocs/op
```

CPU samples 3.44 s：

```text
regexp.(*Regexp).doOnePass  flat 35.17%, cum 87.50%
regexp.(*Regexp).doExecute  cum  97.09%
Manager.Detect              cum  99.42%
```

alloc_space 仅包含 benchmark setup 的 regexp compile、pprof 和 dependency init；steady-state Detect 为零分配。

## V2Board 1.6.0 兼容性

- V2Board API paths、`node_id`、`token`、ETag/304 不变；
- V2Board 1.6.0 routing `regexp:` prefix 仍被移除后按 Go regexp 编译；
- valid rule ID/order/pattern semantics 不变；
- invalid remote rule 从“进程 panic”改为“该轮同步 error + 保留旧 snapshot”；
- empty panel rule 正确清除旧限制；
- user tag 最后 UID segment、illegal report `UID/RuleID` 不变；
- traffic accounting、authentication、limiter 不变。

## go test / vet / race / build

```text
go test ./...       PASS
go vet ./...        PASS
go test -race ./... PASS
go build ./...      PASS
```

sandbox 内普通 test 的唯一失败是 `httptest` 无权 `listen tcp6 [::1]:0`；允许 loopback 后原命令通过。不是代码失败。

## CPU / memory / GC / goroutine / lock

- CPU、B/op、allocs/op：如上；
- heap retained：规则 snapshot 每次变化分配一个短 slice，旧 snapshot 在并发 reader 完成后可回收；未测 service-level retained heap；
- RSS：未测 / 无可靠数据；
- GC cycles/pause：未单独测量；steady-state Detect 归零 allocation 会减少 GC input，但未量化 pause；
- goroutine：未新增 production goroutine；
- mutex/block：rule snapshot 继续通过 `sync.Map` 原子发布，Detect 不持 manager-wide lock；定向 race 通过；未采集到需要归因的新锁等待。

## Release 状态

- Release/tag：未创建；
- `v0.9.0`：未移动；
- Gate 通过后 push 独立分支并 fast-forward `main`。

## 已知风险与未解决问题

1. rule match 仍为 O(n)，100 rule miss/last-hit 约数微秒；当前没有 profile 证明需要更复杂索引。
2. `GetDetectResult.LoadAndDelete` 与恰好同时发生的新 Detect 之间的跨轮归属仍需独立语义审计；mapset 自身 race 未在本轮出现。
3. invalid local rule 被跳过而不是阻止启动；这是可用性优先选择，日志会明确暴露错误。
4. 其他 integration-tag panel fixtures 依赖外部/历史服务，本轮新增 pure HTTP status unit tests，不伪称完成真实 panel integration。
5. 低配 RSS、GC、真实 connection throughput 留到 PHASE 11/12。

## 下一步

进入 PHASE 11/12，在 cgroup/taskset/GOMAXPROCS 的安全近似环境中运行 synthetic active-user/connection/churn 与短 soak；随后修复并验证 release/install chain，只有 Release Gate 全绿才创建 `v0.9.0-r1`。
