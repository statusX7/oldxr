# oldxr

oldxr 是以 XrayR v0.9.0 为固定核心基线、长期兼容 V2Board 1.6.0 的维护型 fork。

项目固定使用：

- XrayR v0.9.0 compatibility baseline；
- xray-core v1.7.5；
- Go 1.20 系列；
- V2Board 1.6.0 legacy API。

本项目不会自动跟随 XrayR v0.9.1 或后续 upstream，也不会用升级 xray-core 代替兼容性修复。

## 安装

安装当前稳定的 XrayR v0.9.0 compatibility maintenance release：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/statusX7/oldxr/master/install.sh) 0.9.0
```

参数 `0.9.0` 是 maintenance channel。安装脚本会明确显示它当前解析到的不可变 release tag，例如 `v0.9.0-r1`，并校验下载 archive 的 SHA256。

也可以显式安装维护版本：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/statusX7/oldxr/master/install.sh) 0.9.0-r1
```

安装后配置文件位于 `/etc/XrayR/config.yml`，管理命令为 `XrayR` 或 `xrayr`。

## 兼容性说明

- `v0.9.0` tag 是永久原始兼容基线，不会移动。
- oldxr 优化维护版使用 `v0.9.0-rN` tag。
- `module github.com/XrayR-project/XrayR` 是代码兼容 identity，不因 GitHub 仓库名改变而重命名。
- V2Board `node_id`、`token`、legacy user/config/submit route、traffic 字段和 VMess `alter_id` 等兼容行为不得删除。

## 工程报告

正式正确性修复、并发修复、性能优化、低资源测试与 Release 验证记录位于：

```text
docs/engineering-reports/
```

项目长期维护规则见 `AGENTS.md`。
