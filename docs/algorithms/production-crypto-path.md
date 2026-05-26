# Production Crypto Path

生产 profile 的目标是密文托管与客户端解密边界，而不是声称教学 PRE 已经生产安全。

- 当前可审查候选：`SECURE_ENVELOPE_V1`，已实现并参与正确性/篡改实验。
- 兼容实验：`RSA_PRE_BASELINE`、`ECC_PRE_BASELINE` 可用于 demo 与比较，响应明确带 `proofStatus=NOT_PRODUCTION_REVIEWED`。
- 后续真正代理转换：选择经过外部审查的 PRE/threshold PRE 库，并在 `CryptoProvider` 下替换；不得自行把 prototype 提升为安全承诺。
