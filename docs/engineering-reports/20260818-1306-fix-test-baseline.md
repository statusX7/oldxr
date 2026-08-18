# PHASE 1：恢复 oldxr 可依赖的 test/vet/race 基线

## 基本信息

- 日期/时区：2026-08-18 13:06 BST（Europe/London，UTC+01:00）
- 阶段：PHASE 1，验证基线
- branch：`fix/test-baseline`
- baseline HEAD：`92f9146c4c13a7f7cf75a79fb827bb023d06a902`
- Go version：`go1.20.14 linux/amd64`
- xray-core version：`github.com/xtls/xray-core v1.7.5`
- module protection：`GOFLAGS=-mod=readonly`
- 测试环境：Debian 12、linux/amd64、8 vCPU、15 GiB RAM

## 问题背景

首次审计和本阶段复现均表明，默认 `go test ./...`、`go vet ./...` 和全仓库 race 无法作为长期 Gate：仓库包含不在生产调用链中的 `common/legocmd` 污染包，多组测试依赖固定 localhost port、公网面板或真实 ACME，并存在无限等待 OS signal、nil panic、错误 Shadowsocks fixture 和 unkeyed literal。

本阶段目标不是通过升级依赖或跳过所有测试制造“绿色”，而是移除有一级证据支持的死代码污染，隔离明确的手工 integration fixture，并为正式兼容目标 V2Board 1.6.0 建立 deterministic 回归测试。

## 复现证据

### common/legocmd

删除前执行：

```bash
go test -count=1 -timeout=5m ./...
go vet ./...
```

两者都在 package loading 阶段失败，主要错误为：

```text
cannot find module providing package github.com/gfw-fuck/XrayR/common/legocmd/cmd
cannot find module providing package github.com/urfave/cli
cannot find module providing package github.com/gfw-fuck/XrayR/common/legocmd/log
missing go.sum entry for github.com/rainycape/memcache
```

代码和历史证据：

- `common/legocmd/` 的 19 个文件只由 oldxr 导入快照 commit `23feadd` 引入。
- 仓库生产源码没有引用 `common/legocmd`，`./main` dependency graph 不包含它。
- 官方 XrayR `v0.9.0` tag 不包含 `common/legocmd/` 目录；官方 `.gitignore` 只有遗留的 `common/legocmd/.lego/` 条目。
- 当前实际证书实现和调用链使用 `common/mylego`，不是 `common/legocmd`。

因此没有引入 `urfave/cli`、`rainycape/memcache` 或错误的 `github.com/gfw-fuck/XrayR` module identity，而是删除不在正式基线中的污染目录。

### 不确定测试

移除 package-loading 阻断后，全仓库测试进一步暴露：

- `api/newV2board`、`api/pmpanel`、`api/proxypanel`、`api/sspanel`、`api/v2raysocks` 使用固定 localhost port 或外部面板 URL。
- `common/mylego/lego_test.go` 使用伪凭据访问真实 Let’s Encrypt directory，并在仓库内生成 ACME account/key artifact。
- `service/controller/controller_test.go` 依赖固定 panel、错误 dispatcher fixture，并无限等待 OS signal。
- `service/controller/inboundbuilder_test.go::TestBuildSS` 未设置 cipher，报 `unknown cipher method`。
- 三个 adapter integration test 共六处 unkeyed `api.DetectResult` literal 阻断 vet。

上述失败不能确定性验证产品行为，也不能在 CI 中复现外部状态。

## 根因

1. 历史导入时把上游 tag 未包含的 `common/legocmd` 工作目录一并带入，却没有迁移 module import 或依赖锁；它从未成为 oldxr 生产路径。
2. 多个 `*_test.go` 实质是开发者手工联调脚本，没有随机端口、受控 server、timeout、cleanup 或 integration 标记。
3. 正式 V2Board legacy adapter 原测试只打印在线面板响应，没有断言兼容字段、route、query 或 traffic body。

## 修改方案

1. 删除 `common/legocmd/` 的 19 个死代码/测试文件，保留官方 v0.9.0 同样存在的 `.gitignore` 历史条目。
2. 给需要真实外部服务的测试添加 `//go:build integration`；默认 Gate 不执行它们，但 `-tags=integration -run '^$'` 和 `go vet -tags=integration` 仍验证其可编译性和静态检查。
3. 把六处 `api.DetectResult` 改为 keyed literal，不借 build tag 隐藏 vet 问题。
4. 把 `api/v2board/v2board_test.go` 重写为 `httptest.NewServer` random loopback fixture。
5. 为 Shadowsocks inbound builder fixture设置 `CypherMethod: aes-128-gcm`。

## 修改文件

- 长期验证规则状态更新：`AGENTS.md`
- 删除：`common/legocmd/` 下 19 个历史污染文件。
- integration 标记：
  - `api/newV2board/v2board_test.go`
  - `api/pmpanel/pmpanel_test.go`
  - `api/proxypanel/proypanel_test.go`
  - `api/sspanel/sspanel_test.go`
  - `api/v2raysocks/v2raysocks_test.go`
  - `common/mylego/lego_test.go`
  - `service/controller/controller_test.go`
- deterministic fixture：`api/v2board/v2board_test.go`
- fixture 修复：`service/controller/inboundbuilder_test.go`

生产运行逻辑修改：0。

## V2Board 1.6.0 兼容性验证

deterministic fixture 直接依据 V2Board 1.6.0 的 `DeepbworkController`、`TrojanTidalabController` 和 `ShadowsocksTidalabController` 建立，已断言：

- legacy route：`Deepbwork`、`TrojanTidalab`、`ShadowsocksTidalab` 的 config/user/submit 路径；
- query：`node_id`、`token`，config 的 `local_port=1`；
- VMess：`inbounds`、`streamSettings.network/security`、WS `path/Host`、`id`、`v2ray_user.uuid/email/alter_id`；
- Trojan：`local_port`、`ssl.sni`、`id`、`trojan_user.password`；
- Shadowsocks：`id/port/cipher/secret`；
- 本地 `SpeedLimit` 和 `DeviceLimit` 到 `api.UserInfo` 的映射；
- traffic submit：`user_id/u/d` 及 POST method；
- `ReportNodeStatus`、`ReportNodeOnlineUsers`、`ReportIllegal` 的 legacy no-op 行为；
- V2ray config 中 routing rule 的现有解释。

ETag response header 已纳入 fixture，但 `If-None-Match`/304 行为尚未实现；它属于后续独立性能阶段，不能把本阶段写成 ETag 已验证。

## 正确性测试结果

### 定向测试

```bash
go test -count=1 -timeout=2m ./api/v2board ./service/controller ./common/mylego
```

结果：通过。

### go test

```bash
go test -count=1 -timeout=5m ./...
```

结果：通过，所有默认 package 成功；无公网 panel、Redis 或 ACME 依赖。V2Board fixture 只绑定随机 `127.0.0.1` port。

### go vet

```bash
go vet ./...
```

结果：通过。

### race

```bash
CGO_ENABLED=1 go test -race -count=1 -timeout=10m ./...
```

结果：通过，未报告 data race。

### integration compile/vet

```bash
go test -tags=integration -run '^$' -count=1 -timeout=5m ./...
go vet -tags=integration ./...
```

结果：两者通过。此命令只编译 integration tests，不连接真实服务。

## benchmark before / after

不适用：本阶段没有生产性能修改，也没有声称 CPU、内存或延迟改善。

## CPU / memory / allocation / GC

- CPU：未测 / 无可靠数据
- RSS：未测 / 无可靠数据
- heap：未测 / 无可靠数据
- `B/op`：未测 / 无可靠数据
- `allocs/op`：未测 / 无可靠数据
- goroutine：未测 / 无可靠数据
- GC：未测 / 无可靠数据
- mutex/block：未测 / 无可靠数据

## build 结果

命令使用 Go 1.20.14、`CGO_ENABLED=0`、`-trimpath` 和 `-mod=readonly` 构建 `./main`。

- output：`/tmp/oldxr-phase1-test-baseline`（不提交）
- size：125,221,498 bytes
- SHA256：`d74ef4f5f844a96787983f03843a622693aee6ef9192c183f600468cb377aff1`
- `go version -m`：Go 1.20.14、linux/amd64、xray-core v1.7.5、`CGO_ENABLED=0`
- 结果：通过

## Release 状态

不适用。本阶段不创建 tag、asset 或 Release，不修改 installer/workflow。

## 已知风险

- `integration` tests 仍需要操作者提供真实 panel/ACME 环境；本阶段只保证其 compile/vet，不宣称外部集成通过。
- 默认 test suite 目前 package 数量有限；后续每个 P0 修复必须增加能够在修复前失败的 deterministic test。
- V2Board test server 使用 loopback socket；受限 sandbox 必须明确允许本地 socket，但不需要公网访问。
- 已移动本轮失败 ACME fixture 产生的未跟踪 artifact，仓库工作树未保留 key 文件；未来 integration test 仍应改为 temp directory 后才能安全实际运行。

## 未解决问题

- P0 traffic accounting lost-update window。
- P0 same UID modified user。
- P0 Controller shared state race。
- P0/P1 Global IP/Device Limit race/boundary/goroutine amplification。
- V2Board ETag/304、Limiter、stats scan、Release chain 等后续阶段任务。

## 下一步

进入 PHASE 2：先用独立 counter/fake report fixture 确定性证明 `Value → Report → Set(0)` 的并发丢失，再实现原子 drain 与失败恢复，验证总字节守恒、连续 report 和 race，不改变 V2Board `user_id/u/d` 语义。
