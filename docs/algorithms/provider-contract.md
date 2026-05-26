# Crypto Provider Contract

`crypto/provider/CryptoProvider` 统一提供 key generation、DEK encapsulation、可选 proxy transform 和 decapsulation；`SchemeDescriptor` 必须公开：

- `schemeId`、`algorithmFamily`、`parameterSpec` 和安全级别。
- `baselineOnly`、`supportsProxyTransform`、`supportsThreshold`。
- `proofStatus` 与 `implementationStatus`。

| Provider | `baselineOnly` | Proxy transform | 用途 |
| --- | ---: | ---: | --- |
| `RSA_PRE_BASELINE` | true | true | 正确性与性能对照 |
| `ECC_PRE_BASELINE` | true | true | 实验性曲线流程对照 |
| `SECURE_ENVELOPE_V1` | false | false | JCA 直接接收方封装候选路径 |

`CryptoProviderRegistry.productionDefault()` 只会选择非 baseline 的已实现 provider；仅存在 baseline 时必须失败。
