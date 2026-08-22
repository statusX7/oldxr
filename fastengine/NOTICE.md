# 第三方代码说明

`src/codec.rs` 的 VMess AEAD/KDF/nonce/framing 实现基于 Shoes commit
`7a5a8ee3bd1c52bc15ec57e074e95e374d41f275` 改写。Shoes 由 Alex Lau
维护并采用 MIT License；其版权与许可条款见 `LICENSE`。

该目录当前仅是 oldxr Phase 7 本地性能与正确性原型，不是可发布引擎。
