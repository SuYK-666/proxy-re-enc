# ECC PRE Baseline

`EccPreScheme` 是 P-256 流程实验实现，服务于教学和性能对照。点解析调用曲线成员/规范编码检查，错误 header 或非规范点会被拒绝。

## 不可承诺点

- 曲线运算为项目内实验实现，未经过侧信道审查或第三方密码学审计。
- recipient-share 流程展示交互式 rekey 绑定，不等价于可部署的安全 PRE 证明。
- production 正式默认路径不得只依赖该实现。

对应负向验证：`EccPreSchemeTest` 中的错误点/篡改 header 拒绝，以及 `CryptoProviderTest` 对生产默认选择的约束。
