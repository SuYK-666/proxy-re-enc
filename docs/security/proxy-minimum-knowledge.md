# Proxy Minimum Knowledge

Proxy 只接收 grant 对应 capsule transformation 请求，不需要 ciphertext 明文、DEK 或 recipient private key。`ProxyNode` 现在记录状态、tenant 范围、允许 scheme、quota、usage 和停用原因。

`ProxyNodeServiceTest` 覆盖 revoked proxy、scheme 不允许和 quota exhausted 拒绝。生产日志不得输出 plaintext、DEK 或 private key 内容。
