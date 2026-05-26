# Package Tamper Tests

`PackageManifest` 在签发时绑定 ciphertext、AAD、capsule、policy/context 与 key version；`issuedManifestHash` 随 package 状态持久化，下载时不能重新“接受”被替换的载荷。

| 变更 | 验证点 | 结果要求 |
| --- | --- | --- |
| ciphertext bit flip/替换 | `ciphertextHash` | `PACKAGE_INVALID` |
| AAD 替换 | `aadHash` | `PACKAGE_INVALID` |
| capsule header/wrapped key 替换 | `capsuleHash` | `PACKAGE_INVALID` |
| grant policy/context 替换 | manifest binding | `PACKAGE_INVALID` |
| manifest 替换 | `issuedManifestHash` | `PACKAGE_INVALID` |

自动化来源为 `PackageVerifierTest` 和 E04 `e04-package-tamper-results.json`。
