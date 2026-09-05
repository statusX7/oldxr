# 内置维护依赖

为确保 `statusX7/oldxr` 是 oldxr 唯一的 GitHub 仓库，并保证 clean checkout 可以独立开发、构建和发布，正式数据路径依赖以源码形式保存在本目录。

| 目录 | 原模块 | 锁定提交 | 许可证 |
|---|---|---|---|
| `xray-core` | `github.com/xtls/xray-core` | `09b25af1d73d0c0e4d276e759a6312f14ba69e81` | MPL-2.0 |
| `gnet` | `github.com/panjf2000/gnet/v2` | `a07009fb328efd011c6558cfd384d96b23f5d572` | Apache-2.0 |

两个目录均由对应精确 Git commit 的 tracked tree 导入，不包含其 `.git` 元数据。完整旧远程历史仅保存在维护者本地归档中，不属于源码或 Release 资产。

不得重新创建 `oldxr-xray-core`、`oldxr-gnet`、`oldxr-giouring`、`xray-core-oldxr` 或其他名称包含 `oldxr` 的独立 GitHub 仓库。后续依赖更新必须直接作为 `statusX7/oldxr` 内的版本维护提交完成。
