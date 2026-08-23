# oldxr

oldxr 是长期兼容 XrayR v0.9.0 配置与用户可观察行为、长期兼容 V2Board 1.6.0 的高性能维护型后端。

项目固定的是兼容合同：

- XrayR v0.9.0 compatibility baseline；
- V2Board 1.6.0 legacy API；
- 现有 `config.yml`、协议安全、计费、限速、规则与无损升级语义。

内部 Go、core 与 data engine 按 Release 锁定并经过回归验证，不作为永久冻结线。本项目不会自动跟随会删除 V2Board 1.6.0 legacy API 的 XrayR v0.9.1 或后续 panel adapter。

## 安装

安装当前稳定的 XrayR v0.9.0 compatibility maintenance release：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/statusX7/oldxr/master/install.sh) 0.9.0
```

参数 `0.9.0` 是 maintenance channel。安装脚本会明确显示它当前解析到的不可变 `v0.9.0-rN` release tag，并校验下载 archive 的 SHA256。

安装后配置文件位于 `/etc/XrayR/config.yml`，管理命令为 `XrayR` 或 `xrayr`。

## 兼容性说明

- `v0.9.0` tag 是永久原始兼容基线，不会移动。
- oldxr 优化维护版使用 `v0.9.0-rN` tag。
- `module github.com/XrayR-project/XrayR` 是代码兼容 identity，不因 GitHub 仓库名改变而重命名。
- V2Board `node_id`、`token`、legacy user/config/submit route、traffic 字段和 VMess `alter_id` 等兼容行为不得删除。

项目长期维护规则见 `AGENTS.md`。
