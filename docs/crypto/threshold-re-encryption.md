# Threshold Re-Encryption Experiment

`ThresholdReEncryptionService` 在 GF(256) Shamir share 原型上增加代理签发层：
每个 assigned proxy 持有独立 Ed25519 key，并对自己的 share digest 签名；
aggregator 只组合通过身份、公钥和摘要验证的唯一 share。

| 配置 | 自动化证据 |
| --- | --- |
| `t=2,n=3` | 恢复成功；一个 share 拒绝 |
| `t=3,n=5` | 恢复成功；少于三个拒绝 |
| 篡改 share | `THRESHOLD_SHARE_INVALID` |

这是实验 rekey material 的分片证明，不是经过公开审查的 threshold PRE
生产协议；达到阈值的代理合谋仍是残余风险。
