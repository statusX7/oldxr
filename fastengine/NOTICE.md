# 第三方代码说明

`src/codec.rs` 的 VMess AEAD/KDF/nonce/framing 实现基于 Shoes commit
`7a5a8ee3bd1c52bc15ec57e074e95e374d41f275` 改写。Shoes 由 Alex Lau
维护并采用 MIT License；其版权与许可条款见 `LICENSE`。

`src/codec.rs` 中相应改写继续遵循上述 MIT License；oldxr 自有的其余
FastEngine 源码按仓库根目录的 MPL-2.0 发布。构建与发布必须同时保留本
说明、Shoes MIT License 和仓库根目录许可证。
