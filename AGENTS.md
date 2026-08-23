# oldxr 项目长期维护规则

## 适用范围

本文件适用于本仓库全部目录。子目录如需增加更具体的 `AGENTS.md`，不得放宽本文件中的兼容性、安全、测试、Git 或 Release 约束。

## 项目使命

`oldxr` 是长期兼容 XrayR v0.9.0 配置与用户可观察行为、长期兼容 V2Board 1.6.0 的高性能维护型后端。项目目标是：

```text
XrayR v0.9.0 config / user-visible compatibility
+ V2Board 1.6.0 完整兼容
+ bug 修复
+ 并发安全
+ 可替换的现代 data engine
+ CPU / 内存 / GC / 高并发深度优化
+ 长期运行稳定性
+ 可验证、可复现的构建与发布
```

本项目冻结的是 compatibility contract，而不是内部 implementation dependency。正确性、安全语义、V2Board 1.6.0 兼容性、现有 `config.yml` 兼容性、traffic accounting、限速、规则、无损升级和长期稳定性优先；Go、xray-core、其他协议引擎、依赖版本、toolchain 与 repository architecture 可以在可归因 A/B、许可和完整回归支持下升级、fork、替换或重构。

## 语言规则

- 与用户交流、计划、进度、审计、风险、测试结果、性能报告和最终总结使用简体中文。
- 新增的面向用户或管理员的人类可读文案原则上使用简体中文；既有兼容字符串不得为中文化而修改。
- 变量名、函数名、类型名、package、文件名、目录名、API 字段、JSON/YAML key、环境变量、URL、Git branch、shell 命令、Go 命令和技术专有名词保持项目原有英文格式。
- 遵循现有注释风格。公开 API 的 GoDoc 如原本使用英文，应继续使用英文。
- Git commit message 必须使用英文，例如 `fix: synchronize controller shared state`。

## 固定兼容合同与可变实现基线

- 固定 compatibility baseline：XrayR v0.9.0 的 `config.yml`、legacy V2Board adapter 和用户可观察行为。
- 正式兼容面板：V2Board 1.6.0。
- `VMess`、`Shadowsocks`、traffic accounting、`SpeedLimit`、`DeviceLimit`、rule、安全语义、安装升级和 rollback 属于 HARD contract。
- 当前稳定回滚实现仍为 Go 1.20、`github.com/xtls/xray-core v1.7.5`，但它们只是历史实现状态，不是未来实现冻结线。
- Go version、xray-core version、其他 dependency、internal engine、toolchain 和 repository architecture 均可在独立实验中升级、fork、替换或重构；只有通过性能、正确性、安全、许可、供应链、跨平台和升级 Gate 的组合才可进入正式版本。
- 当前模块路径 `github.com/XrayR-project/XrayR` 属于代码兼容身份，不得仅为仓库改名而修改。
- 仓库 tag `v0.9.0` 指向导入快照 `23feadd`；它的核心业务源码与官方 XrayR v0.9.0 对应文件一致，但仓库树还包含工作流、依赖和 `common/legocmd` 差异，不能宣称整个 tree 与官方 tag 字节级相同。
- XrayR v0.9.1 及后续版本的 panel/adapter 体系不得替换 legacy V2Board 1.6.0 contract；其内部 bug fix、性能设计或 core 只能作为有边界、可审计的研究和 backport 来源。
- 官方 XrayR commit `5ab352f9c90c7b...` 的 `update: remove old v2board api` 已删除本项目必须保留的 legacy V2Board adapter；任何相似删除均视为兼容性破坏。

不得使用无目的的 `go get -u ./...`、批量依赖漂移或无法归因的 `go mod tidy`。每项依赖/toolchain/core 变化必须隔离 A/B，锁定 source/version/checksum，审计 license 与已知漏洞，并记录性能、正确性、维护和回滚结论。

## V2Board 1.6.0 强兼容契约

### Legacy Panel API

必须保留 `PanelType: V2board` 及以下 legacy route 和语义：

| 协议 | config | user | submit |
| --- | --- | --- | --- |
| VMess/V2ray | `/api/v1/server/Deepbwork/config` | `/api/v1/server/Deepbwork/user` | `/api/v1/server/Deepbwork/submit` |
| Trojan | `/api/v1/server/TrojanTidalab/config` | `/api/v1/server/TrojanTidalab/user` | `/api/v1/server/TrojanTidalab/submit` |
| Shadowsocks | 用户响应推导节点配置 | `/api/v1/server/ShadowsocksTidalab/user` | `/api/v1/server/ShadowsocksTidalab/submit` |

所有请求必须继续支持 `node_id` 和 `token` query 参数。不得把 V2Board 1.6.0 的 legacy API 与较新的 `VProxy`、UniProxy 或其他面板协议混为一谈。

### 强兼容机器字段

- user response 顶层 `data`。
- 通用用户字段 `id`。
- VMess 的 `v2ray_user.uuid`、`v2ray_user.email`、`v2ray_user.alter_id`。
- Trojan 的 `trojan_user.password`。
- Shadowsocks 的 `port`、`cipher`、`secret`。
- traffic submit 数组元素的 `user_id`、`u`、`d`。
- V2ray config 的 `inbounds`；oldxr 对旧式单数 `inbound` 的兼容解析也不得删除。
- V2ray inbound 的 `port`、`streamSettings.network`、`streamSettings.security`，以及 WS、gRPC、TCP、TLS 对应配置。
- Trojan config 的 `local_port` 和 `ssl.sni`。

`alter_id` 即使在现代 VMess 中看起来过时，仍属于本项目的旧面板兼容字段和运行时构建链路，未经真实 V2Board 1.6.0 回归证明不得删除。

### 已确认的 legacy 行为

- V2Board 1.6.0 的 legacy controller 通过 user endpoint 更新 `LAST_CHECK_AT`，通过 submit 消费 `user_id/u/d` 并更新 `LAST_PUSH_AT`。
- legacy API 没有独立的节点状态或在线 IP 上报契约；oldxr 中 `ReportNodeStatus`、`ReportNodeOnlineUsers` 和 `ReportIllegal` 的 no-op 不能仅因“未实现”而删除或擅自改语义。
- legacy API 不下发 speed/device limit；oldxr 的 `SpeedLimit`、`DeviceLimit` 来自本地 panel config。不得假设它们来自 V2Board 1.6.0 response。
- V2Board 的 ETag/304 是可用的优化方向，但引入前必须验证请求头、缓存失效、首次启动、面板重启和错误回退，不得改变 legacy response 解释。
- Shadowsocks 零可用用户、routing rule 顺序、空规则及无效正则等边界行为必须通过 fixture 明确后再修改，不能猜测。

### 兼容性变更要求

任何触及 `api/v2board/`、`api/apimodel.go`、`panel/`、`service/controller/`、`service/controller/userbuilder.go` 或 traffic submit 的修改，都必须附带：

1. V2Board 1.6.0 原始 controller/model/route 证据；
2. oldxr 请求和 response struct 的字段级 diff；
3. config/user/submit fixture 回归测试；
4. VMess、Trojan、Shadowsocks 的受影响协议说明；
5. `alter_id`、TLS、transport、user identity、traffic 和默认值检查；
6. 对 400、304、空数据、超时和面板不可达的错误路径验证。

不能可靠确认的字段必须标记“需要进一步验证”，不得用推测替代兼容依据。

## 参考源可信度

### 一级：正确性和兼容性依据

1. oldxr 当前源码与 Git history；
2. 官方 XrayR v0.9.0 原始源码与 tag；
3. V2Board 1.6.0 原始源码与 tag/branch。

一级依据决定行为、字段、协议和回归结论。出现冲突时，优先保留 oldxr 的已声明兼容目标，并向用户报告差异。

### 二级：开源架构参考

`v2node`、`V2bX`、`Xboard-Node` 及其他许可兼容的开源后端可用于研究和重新实现数据结构、lookup、同步、限速、流量、生命周期、core、engine boundary、构建和性能设计。其 panel protocol 不能覆盖一级兼容依据；内部实现只有通过 oldxr 自身验证后才可采用。

### 三级：文档与 Release 参考

HekiCore 文档和 soga Release notes 只用于发现问题方向、设计 benchmark 和制定性能目标。无法获得源码时必须写“未知”，不得推测内部实现。

## 外部项目研究规则

- 外部项目可用于只读研究、原型、许可兼容的重新实现和有边界集成，也允许据此替换 oldxr 内部架构或 data engine；不得修改 V2Board 1.6.0 contract、无审计复制代码或引入无法归因的大量依赖。
- 新实现更现代、代码更短或声称更快，都不能作为采用依据。
- 必须同时检查优点、缺点、Issues、已知 bug、锁、goroutine、GC、依赖、复杂度、兼容风险和维护成本。
- 只有 oldxr 自身的 test、race、benchmark、pprof 或可复现代码证据能推动实际修改。
- 每项候选设计必须按以下字段记录：

```text
来源项目：
来源位置：
解决的问题：
设计思想：
oldxr 是否存在同类问题：
oldxr 当前实现：
预计收益：
兼容性风险：
实现复杂度：
如何 benchmark：
是否建议采用：
```

- 连接跟踪、用户删除和强制关闭必须特别审计锁顺序；参考项目曾出现 `CloseAll` 持锁回调导致自死锁，不能照抄。
- 自定义 traffic counter 若在上报前直接清零，必须证明并发增量和失败重试不会丢流量。

## 正确性与并发安全

优先级固定为：

```text
P0 correctness
P0 race
P1 severe stability
P1 high-impact performance
P2 medium performance
P3 cleanup
```

- 并发安全优先于性能。不得以降低锁成本为由引入 race、stale state、流量丢失或生命周期错误。
- `nodeInfoMonitor`、`userInfoMonitor`、report task、config watcher、shutdown 和 runtime reload 可能并行执行；不得假设周期不同就不会重叠。
- `Controller` 的 `nodeInfo`、`Tag`、`userList`、task、limiter/rule state 等 shared mutable state 必须有清晰所有权，使用 mutex、immutable snapshot、atomic pointer 或单写者事件循环之一保护。
- mutex 保护的 slice/map/pointer 不得在解锁后由其他 goroutine 原地修改。优先发布 immutable snapshot。
- 不得在持有共享锁时执行 panel HTTP、Redis、磁盘 I/O、core reload、connection close 或其他不受控回调。
- task 的 `Close` 必须停止后续调度，并在需要时等待 in-flight work 结束；仅停止 timer 不代表 goroutine 已退出。
- 新 goroutine 必须有 owner、取消路径、退出条件和等待策略。禁止每事件无限制创建 goroutine。
- ticker、timer、context、connection、response body 和 profile endpoint 必须有明确生命周期。
- runtime reload 必须先验证新状态，并设计失败回退；不得先破坏旧可用状态再无回滚地创建新状态。
- plain map 不能在多个 goroutine 间无锁读写；从 cache 取出的 `*map` 同样不是并发安全容器。
- check-then-insert 型 device/IP/connection limit 必须验证边界与原子性，特别检查 `>=`/`>` 和并发突发。
- rate limiter 必须处理 `WaitN` error、burst、小带宽、大 buffer 和取消 context；不能因忽略 error 而绕过限速。
- 用户删除必须清理或有界保留 runtime user、limiter、IP map、rate bucket、stats counter 和 connection state；清理时必须验证锁顺序。
- 流量统计必须满足“无重复、无遗漏、失败可重试”。读取后、HTTP 成功后再 `Set(0)` 存在并发增量丢失窗口，任何替代方案都必须用确定性并发测试验证。
- 用户 diff 必须区分 add、delete、identity change 和 limit-only change；同一 UID 的 UUID/password/port/alterID 变化不能只加入新用户而遗留旧 runtime identity。
- 规则从非空变为空时必须能清除旧状态；无效 panel 正则不得未经处理直接导致进程 panic。

触及上述路径时，必须添加最小复现 test，并执行相关 `go test -race`。不能用“实际不容易发生”替代 happens-before 证明。

## 性能优化规则

每项优化必须遵循：

```text
发现问题
→ 证明问题存在
→ 建立 benchmark
→ 记录 before
→ 最小修改
→ test
→ race
→ benchmark
→ 记录 after
→ 比较
→ 保留或回滚
```

- 禁止先重构后声称性能改善。
- 必须同时报告 `ns/op`、`B/op`、`allocs/op`；适用时增加 CPU、RSS、heap、goroutine、GC cycles、GC pause、mutex/block contention、latency 和 throughput。
- 不接受只看平均值的结论；使用多轮样本和 `benchstat` 或等价统计比较，记录 Go version、commit、CPU、`GOMAXPROCS`、benchmark 参数及背景负载。
- CPU 优化不能隐藏内存、GC、锁竞争或复杂度回退；cache 优化必须评估 retained memory、失效、stale state 和同步成本。
- 对 `fmt.Sprintf`、string 拼接、JSON、regex、map/slice rebuild、interface 和临时对象的优化，必须由 allocation profile 或 benchmark 证明。
- 不得仅凭理论复杂度直接重写；先测量真实常数、调用频率和数据规模。

当前维护阶段的 CPU 发布判断以同功能、同协议、同 cipher、同注册/活跃用户、同 traffic profile 与同资源限制的 normalized CPU cost 为准：相对 `v0.9.0-r2` 或对应 LegacyEngine 降低至少 30% 为可接受线，降低至少 40% 为优先目标，降低至少 50% 为优秀结果并应尽量保持。性能阈值不得通过降低吞吐、关闭功能、更换 workload、弱化安全语义或省略 control plane 来满足；正确性、兼容性、安全与升级 Gate 不因性能阈值调整而降低。

## 大用户量基准

用户同步、diff、runtime add/delete、limiter update、stats lookup、traffic report 和 config reload 至少评估：

```text
1,000 users
10,000 users
50,000 users
```

- 记录总延迟、每用户成本、峰值 heap、总分配和 GC。
- 标出 O(n)、O(n log n)、O(n²) 和重复全局扫描。
- 多节点场景须检查每个 controller 扫描 global stats 是否形成 O(nodes × counters)。
- 用户 churn benchmark 必须覆盖新增、删除、同 UID identity change、limit-only change 和重复无变化同步。
- 任何 per-user counter/map 必须测量 50,000 用户及“历史上连接过但当前已删除”的 retained memory。

## 大量连接基准

分阶段评估 1k、10k 和更多长连接，不得直接制造会失控的无限负载。至少记录：

- connection setup latency 与吞吐；
- goroutine、heap、RSS、stack、fd、GC 和每连接 retained memory；
- limiter、stats、rule、sniffing、dispatcher 的 CPU/allocation；
- 连接建立/关闭、半关闭、长时间空闲、UDP/XUDP 和用户删除时的资源回收；
- mutex/block profile 和 file descriptor 上限。

压测前必须确认 `ulimit -n`、端口范围、内存预算、超时、停止条件和采样方法。systemd 的 `LimitNOFILE` 不能代替开发 shell 的实际限制。

## Benchmark 规则

- benchmark 应尽量放在被测 package，命名为 `BenchmarkXxx`，避免依赖公网和真实 panel。
- 使用稳定 fixture，预分配输入，避免把测试数据生成成本错误计入被测路径。
- 对 map lookup、user diff、counter scan、limiter、rule match、JSON decode 和 traffic aggregation 分别建立 microbenchmark；另建 controller 级 integration benchmark。
- 至少执行 `go test -run '^$' -bench ... -benchmem -count=10`；高噪声场景增加 benchtime。
- before/after 必须基于相同 Go toolchain、依赖、环境变量和 CPU 配置。
- 性能变更如果 race/test 失败，不得以 benchmark 更快为由保留。

## pprof 与运行时观测规则

- 优先在隔离的开发环境使用 CPU、heap、allocs、goroutine、mutex 和 block profile。
- profile endpoint 默认不得暴露到公网；必须绑定 loopback 或受控管理网络。
- CPU profile 采样窗口应覆盖稳定负载，不把启动、依赖下载或日志洪泛误判为 steady state。
- heap 分析同时查看 `inuse_space`、`inuse_objects`、`alloc_space`、`alloc_objects`，并区分 Go heap 与 RSS。
- 长期运行测试定时记录 `runtime/metrics`、RSS、fd、goroutine 和 GC，比较增长斜率而非单个快照。
- mutex/block profile 需要明确设置采样率；测试后恢复，避免长期生产开销。
- profile 结论必须记录采样命令、持续时间、负载、commit、Go version 和 top/cum call path。

## 测试与验证规则

使用候选明确声明并锁定的 toolchain 和依赖。before/after 必须记录实际版本；常规验证顺序：

```bash
gofmt
go test ./...
go vet ./...
go test -race ./...
go test -run '^$' -bench ... -benchmem
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' -o ... ./main
git diff --check
git status --short
```

- 命令应使用 `-mod=readonly` 或等价保护，避免测试隐式修改 `go.mod/go.sum`。
- 测试失败时先分析 fixture、环境、模块路径、端口、证书、外部服务和真实产品缺陷；依赖升级必须是有证据、可归因的独立实验，不能用来掩盖失败。
- integration test 必须有 timeout、随机可用端口、可取消 context 和确定性退出，禁止无限等待 OS signal。
- 需要 Redis、panel、TLS、网络或特权端口的测试必须显式标注和隔离。
- 修复 race 必须保留能够在修复前触发、修复后通过的回归测试。
- 全仓库验证如果被无关基线问题阻断，必须同时运行受影响 package 的定向验证，并如实报告两者；不得把定向通过写成全仓库通过。
- 已从生产依赖图和官方 v0.9.0 tag 之外清理历史污染目录 `common/legocmd`；不得为恢复该目录而引入旧 `github.com/gfw-fuck/XrayR` import、`urfave/cli` 或未锁定的间接依赖。
- integration test 必须使用 `//go:build integration` 显式隔离，同时仍通过 `-tags=integration -run '^$'` 和相应 vet 保证可编译；不得用 build tag 隐藏静态检查错误。

## Go 工程规则

- Go 语言和标准库最低版本由经验证的正式 toolchain 决定；升级前后必须做同源码 A/B，并同步验证 build、test、vet、race、amd64、arm64、Release 与 installer。
- 依赖必须有必要性、许可、维护、安全、二进制体积、GC 和跨平台评估。
- 允许有 benchmark hypothesis 和 rollback point 的大规模 engine/repository 重构；仍应拆成可审查、可 benchmark、可 bisect 的逻辑提交。
- error 必须保留上下文；不得无故 panic。来自 panel/config 的输入必须验证。
- HTTP response body 必须关闭；request 必须有 timeout/cancel；重试必须有上限和 backoff。
- 不得在 hot path 添加高频 `fmt.Sprintf`、反射、无界 cache、无界日志或 goroutine。
- 公开 struct、JSON tag、mapstructure key 和 config 默认值可能属于兼容接口，修改前必须审计。
- 使用 `gofmt`；遵循现有 package 和命名风格，不把标识符改成中文或拼音。

## 工程报告规则

- 每次正式工程审计、重要正确性修复、并发修复、性能优化、低资源验证和 Release 都必须在仓库外的 `/root/projects/oldxr-reports/` 新建独立 Markdown 报告。
- 文件名使用 `YYYYMMDD-HHMM-phase-name.md`，正文使用简体中文；代码标识符、路径、命令、API 字段和技术专有名词保持英文。
- 报告至少记录日期/时区、阶段、branch、commit/HEAD、Go 与 xray-core 版本、测试环境、证据、根因、方案、修改文件、兼容性、test/vet/race/build、benchmark before/after、风险和下一步。
- 性能报告必须记录可获得的 `ns/op`、`B/op`、`allocs/op`、CPU、heap、RSS、goroutine、GC、mutex/block；无法可靠测量的项目明确写“未测 / 无可靠数据”，不得估算或编造。
- 报告不得包含 token、private key、生产凭据、订阅信息、用户数据或带密钥 URL。
- 所有工程报告、`.pprof`、core dump、临时 binary 和 raw benchmark 输出均不得提交 Git；profile 和 raw 数据分别保存在 `/root/projects/oldxr-reports/profiles/` 与 `/root/projects/oldxr-reports/raw/`。

## Git 工作流

本项目的标准流程：

```text
main
→ git pull --ff-only
→ 创建独立 branch
→ baseline
→ 修改
→ gofmt
→ test
→ vet
→ race
→ benchmark（性能变更）
→ build
→ git diff
→ commit
→ push branch
→ 报告
```

- 日常开发禁止直接 `git push origin main`；只有当前任务得到用户明确授权且阶段 Gate 全部通过时，才可将已验证工作分支以可追踪方式整合并 push `main`。
- 禁止 force push、改写历史和未经用户明确授权的自动 merge、tag 或 Release。
- 未完成 required validation 不得 commit/push；若存在明确的基线阻断，必须先向用户报告并取得指示。
- 一个 branch/commit 聚焦一个可验证主题；不得混入格式化、依赖升级或无关清理。
- commit message 使用英文。
- 不得改写用户已有改动；发现 dirty worktree 时先区分来源并避让。

## Release 工作流

Release 链路必须完整验证：

```text
source
→ build
→ binary
→ package
→ GitHub Release
→ install.sh
→ download
→ unzip
→ systemd
→ update
→ update-shell
```

- 正式仓库和下载来源必须最终统一为 `statusX7/oldxr`。
- workflow branch 必须与默认分支 `main` 一致；不得保留只触发 `master` 而使 CI 静默失效的配置。
- `install.sh`、`XrayR.sh`、service、README 和 GitHub Release asset 名必须相互匹配。
- Release toolchain 应固定到经验证的 Go patch version；不得使用会漂移到未来版本的宽泛范围。
- `geoip.dat`、`geosite.dat` 和第三方资产必须固定版本并校验 hash，避免构建时抓取移动的 `latest` 造成不可复现。
- Release 前必须在干净 checkout 执行 build/test/vet/race 和代表性 cross-build，检查 `go version -m`、版本输出、archive 内容、checksum 与安装/升级路径。
- CGO 默认保持禁用；若改变必须逐平台验证运行时依赖。
- 当前脚本和 workflow 中存在 `statusX7/XR`、`gfw-fuck/XrayR`、`XrayR-project`、`master`、`aiastia/xrayr` 等残留引用。修复应作为独立 Release 任务完成并回归，不得在无关性能变更中顺手修改。
- `main` 是主开发/稳定源码分支；`master` 仅作为通过完整 Release Gate 后的稳定安装入口，不得演变成长期漂移的第二套源码。
- tag `v0.9.0` 是永久原始兼容基线，禁止移动、删除、覆盖或 force-update；oldxr 维护版使用 `v0.9.0-r1`、`v0.9.0-r2` 等递增 tag。
- 安装参数 `0.9.0` 表示 XrayR v0.9.0 compatibility maintenance channel，必须明确解析到当前稳定 `v0.9.0-rN`，日志必须显示实际 tag；显式 `0.9.0-rN` 也应可安装。
- `install.sh` 与 `XrayR.sh update` 必须只从 `statusX7/oldxr` 获取脚本和 Release asset，不得静默回退到 `statusX7/XR` 或任意第三方源。
- Release 至少验证 `XrayR-linux-64.zip` 和 `XrayR-linux-arm64-v8a.zip` 的内容、SHA256、fresh install、update、systemd 与实际 binary 启动；正式发布必须记录 `main`、`master` 和 release tag SHA。
- FastEngine maintenance Release 使用同目录三二进制：`XrayR` 是 V2Board/config compatibility control 与 engine selector，`XrayR-fastengine` 是现代数据面，`XrayR-legacy` 是不支持配置的显式 fallback。构建、installer、备份与回滚必须把三者作为一个不可拆分单元，不能静默遗漏 sidecar。
- Go control 与 LegacyEngine 可使用不同且已锁定的 Go toolchain；Rust FastEngine 必须锁定 Rust target、`Cargo.lock`、第三方许可说明及 dependency audit。Release 报告必须如实注明实际 engine/core，而不能继续笼统声称内部 core 固定为 v1.7.5。

## 兼容平台

当前稳定 r2 Release 配置声明并已在 Go 1.20、`CGO_ENABLED=0` 下做过编译验证的目标包括：

- Linux: amd64、386、arm/v5、arm/v6、arm/v7、arm64、riscv64、mips、mipsle、mips64、mips64le、ppc64le、s390x，以及 mips/mipsle soft-float；
- Windows: amd64、386；
- FreeBSD: amd64、386、arm/v7、arm64；
- OpenBSD: amd64；
- DragonFly BSD: amd64；
- macOS: amd64、arm64；
- Android: arm64。

“可交叉编译”不等于“已在目标系统运行验证”。修改 platform-specific、network、filesystem、service、certificate 或 syscall 行为时，必须缩小声明或增加目标系统验证。oldxr 不以 Docker 为部署、性能或 Release Gate 目标；第三方 OCI 样本的隔离安全研究不改变此规则。

Phase 7 FastEngine 使用 Linux `io_uring`，正式 FastEngine archive 仅声明 Linux amd64 与 arm64；上面的广泛平台列表是稳定 r2 LegacyEngine 的历史构建范围，不得自动沿用为新引擎支持声明。Go control/LegacyEngine 仍以 `CGO_ENABLED=0` 构建，Rust FastEngine 当前依赖目标系统的 glibc 与 `libgcc_s`，必须在归档审计和安装说明中明确。

## 永久禁止事项

永久禁止：

- 用 XrayR v0.9.1+ panel/adapter 替换 legacy V2Board 1.6.0 adapter；
- 无边界 merge、cherry-pick 或同步新版 XrayR，导致 compatibility contract 漂移；
- 无 A/B、license、安全、供应链和回归证据升级 core、依赖或 Go version；
- 删除 `api/v2board`、legacy route、legacy field、JSON tag 或 `alter_id`；
- 改变 V2Board 1.6.0 Panel API 语义；
- 用 VProxy/UniProxy/其他面板 adapter 替换 legacy V2Board adapter；
- 复制 license 不兼容、闭源、破解或来源不明的实现；
- 仅凭外部项目宣传、没有 oldxr prototype 和 benchmark 就声称重构有效；
- 无 benchmark/pprof 证据声称性能提升；
- 为让测试变绿而跳过失败、改锁文件或升级依赖；
- 无界 goroutine、cache、queue、重试或负载测试；
- 未经验证直接 push main、force push、merge、tag 或 Release。

## 完成定义

代码任务只有同时满足以下条件才算完成：

1. 行为和兼容目标有一级证据；
2. 修改范围与 hypothesis 对应、可审查、可 bisect，未混入无关变化；
3. V2Board 1.6.0 强兼容字段和调用链未破坏；
4. 已运行适用的 `gofmt`、test、vet、race、build；
5. 性能修改有可复现 before/after benchmark，必要时有 pprof；
6. 并发修改有 race regression test 和生命周期说明；
7. 大用户量/大量连接影响已按风险评估；
8. `git diff`、`git diff --check` 和工作树状态已审查；
9. 所有失败、跳过、环境限制、兼容风险和待验证项已用简体中文如实报告；
10. 仅在 required validation 通过且用户授权时 commit/push；整合 `main`、建立 `master`、创建 tag 或 Release 还必须具有当前任务的明确授权并通过对应 Gate。
