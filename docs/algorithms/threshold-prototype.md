# Threshold Prototype

`ThresholdSecretSharing` 使用 GF(256) 上的 Shamir sharing 将实验性 re-key material 分为 `n` 份，至少 `k` 份才恢复。E13 覆盖 `k=2,n=3` 和 `k=3,n=5`。

这是创新性与治理流程实验，不是经过证明的 threshold PRE：它未定义分布式代理变换证明、恶意 share 验证或侧信道防护，不能用于 production 安全承诺。
