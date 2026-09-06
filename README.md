# oldxr

oldxr v1.1.0 是既有实验运行时的单 Go 二进制预发布快照，沿用 XrayR 0.9.0 配置与 V2Board 1.6.0 接口。

本版尚未通过完整连接稳定性验收，不作为默认更新推荐。请先在非生产环境验证；需要稳定运行时请继续使用现有正式版。历史性能记录不代表本版已获完整性能验收。

## 安装或升级

```bash
bash <(curl -Ls https://raw.githubusercontent.com/statusX7/oldxr/v1.1.0/install.sh) 1.1.0
```

该独立入口支持全新安装和现有安装升级。已有 `config.yml`、自定义 route/outbound/inbound、DNS、rulelist 和证书文件会原样保留；启动验证失败时自动回滚。完整 0–13 管理菜单保持不变。

提供使用 Go 1.27.0 构建的 Linux amd64 与 arm64 资产及 SHA256 校验文件。amd64 使用 GOAMD64=v1；arm64 为交叉构建，未完成本版实机稳定性验收。

## 兼容范围

- V2Board 1.6.0 legacy API
- XrayR 0.9.0 `config.yml`
- VMess、Shadowsocks、TCP、UDP
- traffic accounting、SpeedLimit、DeviceLimit、online IP 与 rule

## License

[Mozilla Public License Version 2.0](LICENSE)
