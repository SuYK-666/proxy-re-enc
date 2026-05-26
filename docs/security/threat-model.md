# Threat Model

| 资产 | 威胁 | 控制 | 剩余风险 |
| --- | --- | --- | --- |
| 文件正文/DEK | storage 或 proxy 读取明文 | 客户端 AEAD、服务端无 plaintext route | 接收方合法解密后的离线副本 |
| Capsule | 替换、跨 grant 重放 | AAD/context、manifest、scoped rekey | baseline 密码协议未经正式审计 |
| 授权 | 跨租户、过期、限次绕过 | object auth、ABAC evaluator、原子下载计数 | 多实例需数据库事务 |
| Proxy | 被禁用节点继续转换 | role、状态、scheme 白名单、quota | 真实部署需 mTLS/IAM |
| Audit | 删除、改写、重排 | hash-chain、Merkle proof/checkpoint | 外部不可篡改 anchor 待接入 |
| 依赖/镜像 | 供应链漏洞 | CI、SBOM、dependency scan、non-root image | 扫描数据库更新可用性 |

攻击者模型包括半可信服务端、被窃取但无客户端私钥的存储快照读取者、越权用户、恶意请求者和被撤销代理。服务端应用自身被完全攻陷后无法替代 KMS/HSM 的保护能力。
