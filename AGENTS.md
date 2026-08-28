# oldxr 1.0.x 项目规则

本文件适用于本仓库及其所有子目录。若与最新用户要求冲突，以最新用户要求为准。

## 产品身份与源码基线

- `1.0.x` 是单一 Go 二进制产品线；当前补丁版本为 `v1.0.1`，binary version 显示 `XrayR 1.0.1`。
- 开发基线必须是官方 `XrayR v0.9.0` commit `f95825395d192498adfc533ab925943088408cb4`；不得从 r3/r4 删除 Rust 后伪装成官方基线。
- 历史 `v0.9.0`、`v0.9.0-r1`、`v0.9.0-r2`、`v0.9.0-r3`、`v0.9.0-r4` tags 不移动、不删除、不覆盖。
- `v1.0.x` production package只包含一个主要运行二进制 `XrayR`。禁止依赖 `XrayR-fastengine`、`XrayR-legacy`、Rust runtime或三二进制 selector。

## 不可破坏的兼容合同

- 必须保持 V2Board 1.6.0 legacy API 和 XrayR 0.9.0 `config.yml` user-visible compatibility。
- 必须保持 VMess、Shadowsocks、TCP、UDP、traffic accounting、online IP、SpeedLimit、DeviceLimit、rule、ETag与用户生命周期语义。
- 必须保持 DNS、routing、`RouteConfigPath`、`OutboundConfigPath`、`InboundConfigPath`、custom files、ProxyProtocol、fallback、TLS/cert等官方 v0.9.0功能。
- 用户的 `config.yml`、`route.json`、`custom_outbound.json`、`custom_inbound.json`、`dns.json`、`rulelist` 和 cert/key 默认只读保留；升级不得重写或迁移其内容。
- Debian 11与Ubuntu 20.04是硬兼容目标；优先使用 `CGO_ENABLED=0`，禁止 `target-cpu=native`等不可移植构建。
- 正式 installer 必须支持 fresh install与官方 XrayR v0.9.0无损升级；启动/健康检查失败必须自动回滚。

## 实现边界

- Go、xray-core与必要依赖版本可以升级，但每次变化必须有同源 A/B 性能证据、兼容验证、安全审计和license审计。
- 允许在单一Go二进制内部深度重构data path、socket ownership、I/O reactor、dispatcher、transport/pipe、协议handler与freedom outbound之间的连接模型；允许维护可追踪的xray-core Go fork或兼容shim。
- common-case fast path可以绕过旧generic pipe/dispatcher handoff，但必须在连接建立时完成route、outbound、traffic、SpeedLimit、DeviceLimit、rule和online-IP绑定；不支持的配置必须无损走原generic path，禁止静默降级。
- 允许跨多个Go package重构和较大代码改动，不再要求局限于单一package；每个架构里程碑仍须独立可关闭、可回滚，并用same-P 1000Mbps A/B证明收益来源。
- 禁止新建平行独立FastEngine产品、重新发明VMess/SS密码协议、用Rust/C替换data plane、恢复多二进制selector或把项目改成非Go后端。
- r1/r2历史修复不得无脑cherry-pick：先在官方基线用测试复现，再移植最小逻辑修复。
- 不得通过关闭功能、改变轮询/上报周期、降低并发/吞吐、减少站点/用户、改变cipher、安全或统计语义获得性能结果。

## 性能与发布 Gate

- 正式主负载：10个独立 V2Board 1.6.0 sites、1000 registered/site、25 VMess + 25 SS active/site、500 TCP connections、4KiB/application write、1000Mbps aggregate application payload（500Mbps upload + echo返回500Mbps download）。
- 正式server固定4 vCPU/4GiB；1C1G只用于maximum-sustainable辅助结果。发布主判定使用独立物理/云Proxy Host，暂不可用时使用独立KVM virtio P-path并明确标注；本机veth/netns只作系统下界、开发回归和调度诊断，loopback不得作为Release Gate。
- 原版与candidate必须使用相同硬件、CPU affinity/quota、MemoryMax、kernel、完整config/route/outbound/rulelist、用户、连接、流量、功能开关、warmup和measurement。负载发生器仍以1000Mbps aggregate application payload为目标；执行时实测吞吐达到`950Mbps`即通过筛选与正式throughput Gate，CPU按实际成功传输的application bytes归一化。不得为了过Gate主动降低发送计划、连接数或功能。
- CPU发布硬目标：在正式P-path 1000Mbps固定吞吐主负载中，candidate cgroup normalized CPU cost `<=70%` exact official v0.9.0，即改善`>=30%`。`30%–40%`可接受，`>=40%`为优先目标；低于`30%`不得发布`v1.0.x`。Mixed必须达到该Gate；VMess-only和SS-only各自目标`>=20%`且任何一个不得回退超过`5%`。同时报告same-P代码收益、task-clock ms/MB和CPU/Mbps，不得把单纯P-width变化冒充源码收益。
- RAM硬目标：candidate RSS `<=50%` official，并记录heap、objects、goroutines、FD和时间斜率。
- 筛选至少3轮、warmup至少30秒、measurement至少60秒；正式结果至少10轮交叉/随机顺序且measurement至少180秒，不得挑最好一次。
- 主测试必须开启traffic accounting、online IP/device、SpeedLimit、DeviceLimit、route/outbound/rulelist、panel polling/submit与UDP support。
- 任一CPU、RAM、功能、OS、soak、安全、升级或rollback Gate失败时，不得发布`v1.0.x`、不得更新master安装入口、不得宣称完成；用户明确接受且在Release notes完整披露的特定安全例外除外，该例外不得自动延伸到其他版本。

## 证据驱动开发

- 修改前先对官方基线采集CPU/heap/alloc/goroutine/mutex/block/syscall profile；只优化top hotspot。
- 每个性能patch应独立、可回滚，并记录hypothesis、targeted test、system benchmark和保留/回退结论。
- 已证伪的固定/adaptive pipe threshold、zero-wait drain、只减少goroutine或allocation、无4KiB收益的drop-in modern core不得机械重复。
- 允许在新socket ownership或direct relay架构下重新验证旧pipe相关假设，但必须明确说明机制为何不同；不得把旧参数实验原样重复。
- `copyInternal`的cumulative值不得当作flat CPU；必须区分user copy、syscall、crypto、netpoll、scheduler、GC与wrapper成本。
- 正式结果必须保持payload exact和traffic守恒：`successfully transferred = reported + pending + retiring-user pending`。

## 测试与审计

- Go变更最终执行`gofmt`、`go test ./...`、`go vet ./...`、`go test -race ./...`、`govulncheck ./...`与`go mod verify`。
- installer/manager最终执行`bash -n`与`shellcheck`，correctness类告警必须修复。
- 必须覆盖VMess TCP、SS AES-128-GCM TCP/UDP、完整示例route/outbound/rulelist、traffic、limit/device/online-IP、用户增删禁用/credential更新、panel失败恢复与同站点隔离。
- 必须审计race、goroutine/FD/counter/limiter/timer leak、retry/busy loop、deadlock、partial write、close、reload与retiring traffic。
- 最终soak最低：Debian 11 6小时、Ubuntu 20.04 2小时、Debian 12 2小时；持续采集RSS/heap/object/goroutine/FD/open connection斜率。
- Release至少构建`linux/amd64`与`linux/arm64`单Go二进制ZIP；Docker不属于本产品部署、性能或Release Gate。

## Git、报告与交流

- oldxr 唯一允许使用的 GitHub 仓库是 `https://github.com/statusX7/oldxr`。
- 禁止新建、上传、迁移或保留任何其他名称中包含 `oldxr` 的 GitHub 仓库，包括 `oldxr-gnet`、`oldxr-xray-core`、`oldxr-giouring` 等独立依赖仓库。
- oldxr 的正式源码、必要维护依赖、版本更新、tag 和 Release 必须统一进入 `statusX7/oldxr`；需要维护的 fork 源码应放入本仓库受控目录，不得另建远程仓库。
- 删除旧 GitHub 仓库不授权删除任何对应本地源码、配置、构建产物、实验结果或 Git mirror；本地证据必须完整保留。
- 任何与 oldxr 无关的 GitHub 仓库均不在操作范围内，禁止修改、删除、重命名或迁移。
- 不force push，不重写/删除历史tag；实验只在独立branch，Gate通过前不merge main/master。
- Git commit message保持英文，每个commit只解决一个逻辑问题。
- 性能、pprof、perf、内部研究、审计和升级报告只写入`/root/projects/oldxr-reports/go-v1/`，不得提交GitHub。
- GitHub只保留production source、必要tests/fixtures、build/install scripts、AGENTS与极简README。
- 所有用户可见交流和本地人类可读报告使用简体中文；代码标识符、配置key、路径、命令、API字段和commit message保持英文。
