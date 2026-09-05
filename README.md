# oldxr

oldxr 1.x 是兼容 XrayR 0.9.0 配置与 V2Board 1.6.0 的单一 Go 二进制维护线。

## 安装或升级

```bash
bash <(curl -Ls https://raw.githubusercontent.com/statusX7/oldxr/master/install.sh) 1.0.3
```

当前公开安装版本为 v1.0.3，v1.1.0 暂停提供。

该命令支持全新安装，以及从官方 XrayR v0.9.0 无损升级。已有 `config.yml`、自定义 route/outbound/inbound、DNS、rulelist 和证书文件会原样保留；启动验证失败时自动回滚。

## 兼容范围

- V2Board 1.6.0 legacy API
- XrayR 0.9.0 `config.yml`
- VMess、Shadowsocks、TCP、UDP
- traffic accounting、SpeedLimit、DeviceLimit、online IP 与 rule

## License

[Mozilla Public License Version 2.0](LICENSE)
