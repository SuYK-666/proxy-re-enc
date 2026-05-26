# Log Redaction

`LogSanitizer` 对 `authorization`、`token`、`privateKey`、`dek`、`plaintext`、
`rekeySecret` 以及 bearer token 值进行脱敏。`LogSanitizerTest` 验证敏感
marker 不保留在清洗后的操作消息中。

生产接入规则：任何审计 detail 或应用日志在包含外部请求内容前必须先调用
sanitizer；禁止记录 ciphertext 解密结果、DEK 或 private key material。
