# oldxr self-contained Release 链修复报告

## 基本信息

- 日期/时区：2026-08-18，Europe/London（UTC+1）
- 阶段：Release chain remediation / pre-release Gate
- branch：`fix/release-chain`
- base HEAD：`6eecd74449405c237cd2a48141ea6d878757a0e4`
- 本报告与 Release 链修改：由本阶段同一逻辑提交纳入
- Go：`go1.20.14 linux/amd64`
- xray-core：`github.com/xtls/xray-core v1.7.5`
- XrayR 基线：v0.9.0
- planned maintenance release：`v0.9.0-r1`

## 问题背景与证据

修复前的发布链存在以下不可接受状态：

- `.github/workflows/merge-upstream.yml` 每日从 `gfw-fuck/XrayR` merge 并 push `master`，与固定 v0.9.0 基线冲突；
- `.github/workflows/release.yml` 在普通 `master` push 构建，Go 使用漂移范围 `^1.19`；
- Release 每次从 v2fly latest API 选择 geodata，source 相同也可能产生不同 archive；
- `install.sh`、`XrayR.sh install/update/update_shell` 与菜单仍指向 `statusX7/XR/master`；
- `install.sh` 对未知 architecture 静默回退 amd64，并在下载/校验前删除已安装目录；
- Release 只有多种 digest sidecar，没有 installer 实际执行的 SHA256 verification；
- Docker workflow 发布到第三方 `aiastia/xrayr`；
- CodeQL、Release 与 Docker 主要围绕 `master`，默认开发分支 `main` 的行为不可追踪；
- README 只有单个字符 `3`，没有正式安装和 compatibility channel 说明。

## 修改方案

### 固定基线与 workflow

- 删除 `.github/workflows/merge-upstream.yml`，停止任何自动 upstream merge。
- Release 只由 `v0.9.0-r*` tag 或人工 `workflow_dispatch` 触发。
- GitHub Actions Release/CodeQL 显式使用 Go 1.20.14 和 `GOFLAGS=-mod=readonly`。
- tag Release 在 build 前执行 `go test ./...`、`go vet ./...`、`go test -race ./...`。
- CodeQL 改为跟踪 `main`。
- Docker 改为 tag/manual 触发并发布 `ghcr.io/statusx7/oldxr`。
- Dockerfile 固定 `golang:1.20.14-alpine3.18` 与 `alpine:3.18`。通过 Docker Hub API 确认两个 tag 实际存在；本机未安装 Docker，因此本地 image build 为“未测”，由 tag workflow 验证。

### 可重复打包

新增 `scripts/build-release.sh`，统一本地与 GitHub Actions 的 build/package 行为：

- `CGO_ENABLED=0`；
- `-trimpath -ldflags '-s -w -buildid= -X main.version=0.9.0-rN'`；
- archive 文件名保持 `XrayR-<friendly-name>.zip`；
- archive 内包含 binary、config、JSON/rulelist、README、LICENSE、`XrayR.service`、`XrayR.sh`、`geoip.dat`、`geosite.dat`；
- 文件排序、timestamp 与 zip extra field 固定；
- 每个 archive 生成 `<archive>.sha256`。

geodata 不再访问 moving latest，直接使用 tag source 中受 Git 追踪的文件：

```text
main/geoip.dat
SHA256 526220535d93b5eea0a1ae7f76c28ecaae8929d122e1b6f36dfc8bf1e294a768

main/geosite.dat
SHA256 98dcbfc80819da9030ef05320f6a44730c0f525eb9fd66fbd7ceb5d17215f84b
```

这会牺牲“每次 Release 自动拿到最新规则”的便利，换取 tag source 与 asset 可追踪、可复建。后续 geodata 更新必须作为显式变更审查其来源与 hash。

### maintenance channel 与安装安全

`install.sh` 现在固定：

```text
0.9.0 / v0.9.0 / empty
→ v0.9.0-r1
```

显式 `0.9.0-rN` / `v0.9.0-rN` 仍受支持，其他版本拒绝。安装日志显示实际 tag。

安装顺序改为：

```text
resolve version
→ download archive + .sha256
→ sha256sum --check
→ unzip 到临时目录
→ 检查 required files
→ 执行 staged binary -version
→ 在 INSTALL_DIR 同目录准备 candidate
→ stop
→ 原目录移动为 previous
→ 原子切换 candidate
→ service/config/manager activation
→ start/check（update）
→ activation 失败恢复 previous binary
```

下载、checksum 或 archive structure 失败发生在 stop/replace 之前，不会破坏现有安装。配置文件在 update 时保留；fresh install 写入示例配置但不在用户配置 panel 前盲目启动。

### 管理脚本

`XrayR.sh` 的 `install`、`update`、`update_shell` 全部使用 `statusX7/oldxr/master`。installer 先下载到 `mktemp`，curl 失败直接返回，不再让空 process substitution 被当成成功。`XrayR update` 默认进入 `0.9.0` maintenance channel。

### 文档与测试

- 重写 README，明确项目基线、安装命令、maintenance channel 与 immutable `v0.9.0` tag。
- 新增 `scripts/test-release-install.sh`，使用临时 root 和 mock systemctl，不修改开发机 `/usr/local`、`/etc` 或 `/usr/bin`。
- 新增 `scripts/fixtures/release-empty-config.yml`，用于 packaged daemon 的 transient systemd 启动测试。

## 修改文件

- `.github/workflows/codeql-analysis.yml`
- `.github/workflows/docker.yml`
- `.github/workflows/merge-upstream.yml`（删除）
- `.github/workflows/release.yml`
- `Dockerfile`
- `README.md`
- `XrayR.sh`
- `install.sh`
- `scripts/build-release.sh`
- `scripts/test-release-install.sh`
- `scripts/fixtures/release-empty-config.yml`
- `docs/engineering-reports/20260818-1535-fix-release-chain.md`

生产 Go 源码修改：0。`go.mod` / `go.sum` 修改：0。

## 本地 Release 验证

### Linux amd64

- `scripts/build-release.sh linux amd64 '' linux-64 v0.9.0-r1 ...`：通过。
- binary：Go 1.20.14、`CGO_ENABLED=0`、xray-core v1.7.5。
- `XrayR -version`：`XrayR 0.9.0-r1`。
- archive：13 个 required files，binary mode 755。
- 同一 HEAD/working tree 重复 build 的 archive byte-for-byte 相同：通过。

pre-commit working tree 的 SHA256 不是正式 Release hash，因为 Go VCS metadata 会记录当前 revision/dirty state；本报告不把该临时 hash冒充最终 asset hash。最终 clean tag build hash必须记录在 Release/final report。

### Linux arm64

- cross-build/package：通过。
- `go version -m`：Go 1.20.14、`CGO_ENABLED=0`、xray-core v1.7.5。
- archive checksum verification：通过。
- 无 arm64 runtime 硬件或 emulator，因此 binary runtime：未测 / 无可靠数据。

### 全部 workflow target

使用 Go 1.20.14、`CGO_ENABLED=0`、同一 ldflags 逐项交叉编译，以下全部通过：

- Linux：amd64、386、arm/v5、arm/v6、arm/v7、arm64、riscv64、mips、mipsle、mips64、mips64le、ppc64le、s390x；
- Linux mips/mipsle softfloat：通过；
- Windows：amd64、386；
- macOS：amd64、arm64；
- FreeBSD：amd64、386、arm/v7、arm64；
- OpenBSD：amd64；
- DragonFly BSD：amd64；
- Android：arm64。

以上只证明 cross-build，不证明目标 OS runtime。

### GitHub Actions / Docker references

通过各官方 GitHub repository 的 `refs/tags` 只读查询确认 workflow 使用的 major tag 均存在：

```text
actions/checkout@v4
actions/setup-go@v5
actions/upload-artifact@v4
actions/download-artifact@v4
github/codeql-action@v3
docker/setup-qemu-action@v3
docker/setup-buildx-action@v3
docker/login-action@v3
docker/metadata-action@v5
docker/build-push-action@v6
```

## 安装、更新与失败路径回归

隔离测试通过：

- `0.9.0 → v0.9.0-r1` channel resolution；
- fresh install archive extraction；
- required files；
- binary version；
- service `WorkingDirectory` / `ExecStart` wiring；
- manager script 与 `xrayr` symlink；
- update 保留 `/etc/XrayR/config.yml`；
- update 调用 service start/status；
- `XrayR.sh update 0.9.0` 同一 channel；
- 损坏 archive 被 SHA256 拒绝；
- checksum failure 后已安装 binary hash 不变；
- 不兼容参数 `0.9.1` 被拒绝。

packaged amd64 binary 使用 `Nodes: []` fixture 作为 transient systemd unit 启动：

```text
ActiveState=active
SubState=running
ExecMainStatus=0
MemoryCurrent=71020544
TasksCurrent=12
```

随后 `systemctl stop oldxr-release-r1-test.service` 正常完成。该测试证明 binary 可以作为 systemd daemon 启动/停止，但不是 V2Board 协议或真实 service file 的生产安装测试。

## Go 工程验证

提交前最终命令结果填写如下：

- `bash -n install.sh XrayR.sh scripts/build-release.sh scripts/test-release-install.sh`：通过。
- `actionlint v1.6.27 .github/workflows/*.yml`：通过；工具安装在 `/tmp`，未修改项目 module。
- `go test ./...`：通过。
- `go vet ./...`：通过。
- `go test -race ./...`：在允许 loopback 的隔离上下文通过。
- Linux amd64 build：通过。
- Linux arm64 build：通过。
- `git diff --check`：通过。

## Benchmark / CPU / memory / GC

本阶段修改 shell/workflow/package，不修改 runtime hot path，因此没有合理的 before/after runtime benchmark：

- `ns/op`：不适用；
- `B/op`：不适用；
- `allocs/op`：不适用；
- CPU before/after：不适用；
- heap/GC before/after：不适用；
- RSS：仅记录 transient empty-node daemon 的 cgroup `MemoryCurrent=71,020,544 B`，不是生产 workload；
- goroutine：未测 / 无可靠数据；
- mutex/block：未测 / 无可靠数据。

## V2Board 1.6.0 兼容性影响

无 panel/runtime Go 源码、module 或 dependency 变化。archive 的 default config、geodata 和 binary 均来自同一 tag source；V2Board API path、JSON fields、traffic semantics、runtime tag 和 authentication 未修改。

## Release 状态

- `v0.9.0` tag：未移动、未删除。
- `v0.9.0-r1`：尚未创建。
- GitHub Release：尚未创建。
- `master`：尚未建立/更新。
- public exact install command：尚未验证。
- Docker publish：尚未执行。

本阶段报告只证明 pre-release chain 和本地 Gate；正式 tag、asset SHA256、master SHA、fresh/update online 验证将在 Release/final report 中记录。

## 已知风险与未解决问题

- GitHub-hosted workflow 尚未在本提交上实际运行；YAML/schema、CodeQL 与 Docker build 必须以远程 Actions 结果为最终依据。
- Docker 本地 build 未测；本机没有 Docker/Podman。
- arm64 仅 cross-build，未做真实 runtime。
- exact public URL、`XrayR.sh update_shell` 和 GitHub Release assets 只能在 push/tag/release 后验证。
- fresh install 默认示例 panel 不可用，因此 installer 不自动启动；用户配置后启动。Release Gate 使用 empty-node fixture 验证 daemon lifecycle。
- installer rollback 当前保证 previous binary directory 恢复；service/manager script 会保持新版内容。由于它们只决定同一 oldxr 路径/channel，不会把下载源回退到 `statusX7/XR`。

## 下一步

1. 完成 final test/vet/race/build 和 diff review，push 工作分支并 fast-forward main。
2. 从 clean release commit 重建 amd64/arm64 assets并记录最终 SHA256。
3. 建立 `master` 稳定入口，创建 immutable `v0.9.0-r1` tag 与 GitHub Release。
4. 从 public `master/install.sh` 在临时 root 执行 exact channel、fresh/update/update-shell 回归。
5. 记录 main/master/tag SHA、Release URL、asset hashes 与 remote Actions 结果。
