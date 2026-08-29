# 内置维护依赖

为确保 `statusX7/oldxr` 是 oldxr 唯一的 GitHub 仓库，并保证 clean checkout 可以独立开发、构建和发布，正式数据路径依赖以源码形式保存在本目录。

| 目录 | 原模块 | 锁定提交 | tracked tree | 许可证 |
|---|---|---|---|---|
| `xray-core` | `github.com/xtls/xray-core` | `7520b4ac63c185f4e615c2ea76df6fb28d56e37b` | `738e2acf4d4f720a0c83b6565a604a255571fa36` | MPL-2.0 |
| `gnet` | `github.com/panjf2000/gnet/v2` | `a07009fb328efd011c6558cfd384d96b23f5d572` | `b7bce2c4937a1d21765de72d6da82b3c7703096c` | Apache-2.0 |
| `giouring` | `github.com/pawelgaczynski/giouring` | `ea4211d9fc24fc31ca944514b596939843688331` | `20949d8b07ee849de7b50fc9dbde8fcf2a57a349` | MIT |

三个目录均由对应精确 Git commit 的 tracked tree 导入，不包含其 `.git` 元数据。`xray-core/go.mod` 仅为独立测试改用相邻目录的相对 `replace`；其他 core 源码逐 blob 保持锁定提交内容。

不得重新创建 `oldxr-xray-core`、`oldxr-gnet`、`oldxr-giouring`、`xray-core-oldxr` 或其他名称包含 `oldxr` 的独立 GitHub 仓库。后续依赖更新必须直接作为 `statusX7/oldxr` 内的版本维护提交完成。
