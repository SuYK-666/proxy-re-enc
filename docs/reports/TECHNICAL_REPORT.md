# 技术报告：基于代理重加密的数据安全管理算法实现

## 1. 项目概述

本项目使用 Java 实现代理重加密数据安全管理原型。系统面向云端数据共享场景：数据拥有者 Alice 将加密数据上传到云端，在不暴露明文和原始数据密钥的前提下，授权 Bob 访问数据。代理服务器只负责密文胶囊转换，不能直接获得明文。

实现语言为 Java，构建方式为 Maven，测试框架为 JUnit 5。

## 2. 总体架构

源码结构：

```text
src/main/java/com/example/pre
  app        DemoApplication / BenchmarkApplication
  crypto     PRE 接口、RSA-PRE、ECC-PRE、AES-GCM、KDF
  model      用户、密文数据包、重加密数据包、审计事件
  service    用户服务、数据安全服务、授权服务
  storage    内存仓储
  util       字节处理、安全随机数、计时工具
```

核心流程：

```text
明文数据
  -> 生成随机 DEK
  -> AES-256-GCM 加密数据
  -> RSA/ECC PRE 封装 DEK
  -> 云端保存密文和胶囊
  -> Owner 生成 reKey
  -> Proxy 转换胶囊
  -> Recipient 解封装 DEK
  -> Recipient 解密数据
```

## 3. 混合加密设计

系统没有直接用 RSA 或 ECC 加密文件内容，而是使用混合加密：

1. 文件内容由 AES-256-GCM 加密。
2. PRE 算法只封装随机数据密钥 DEK。
3. 授权共享时，代理只转换 DEK 胶囊，不重新加密文件内容。

这种设计使 PRE 操作耗时与文件大小基本无关，大文件只影响 AES-GCM 加解密性能。

## 4. RSA-PRE 实现

RSA-PRE 位于：

```text
src/main/java/com/example/pre/crypto/rsa
```

实现要点：

1. `RsaCommonModulusParameters` 生成共享 RSA 模数 `N` 和 `phi(N)`。
2. 所有用户使用同一个 `N`，但拥有不同公开指数 `e_i` 和私钥指数 `d_i`。
3. 为避免最直接的共同模数攻击，公开指数加入共享因子 `h`：

```text
e_i = h * t_i
```

4. 数据密钥封装：

```text
c_A = s^{e_A} mod N
kek = SHA-256("RSA-PRE-KEM" || s)
wrappedDEK = AES-GCM(kek, DEK)
```

5. 重加密密钥：

```text
rk_A_to_B = d_A * e_B mod phi
```

6. 代理转换：

```text
c_B = c_A^{rk_A_to_B} mod N = s^{e_B} mod N
```

7. Bob 解封装：

```text
s = c_B^{d_B} mod N
```

安全说明：该 RSA 方案仍是教学原型。共同模数 RSA 不适合生产系统，报告中将其作为理解 PRE 指数转换的实验方案。

## 5. ECC-PRE 实现

ECC-PRE 位于：

```text
src/main/java/com/example/pre/crypto/ecc
```

实现要点：

1. 使用 P-256 参数。
2. 实现教学型点加、点倍加、标量乘和 SEC1 未压缩点编码。
3. 数据密钥封装：

```text
C1 = r * G
S_A = r * P_A = r * x_A * G
kek = SHA-256("ECC-PRE-KEM" || encode(S_A))
wrappedDEK = AES-GCM(kek, DEK)
```

4. 教学型交互式重加密密钥：

```text
rk_A_to_B = x_A * x_B^{-1} mod n
```

5. 代理转换：

```text
C1' = rk_A_to_B * C1
```

6. Bob 解封装：

```text
S_B = x_B * C1' = x_A * r * G
```

安全说明：该 ECC 方案是交互式教学原型，不抗代理与 Bob 合谋。真实系统应使用 Umbral 类门限 PRE 或基于双线性配对的 PRE。

## 6. 应用场景

本实现主 Demo 为企业文档共享：

1. Alice 加密上传文档。
2. Bob 未授权直接解密失败。
3. Alice 授权 Bob。
4. Proxy 转换密钥胶囊。
5. Bob 成功解密。
6. Charlie 无权解密失败。

报告分析中还覆盖医疗数据委托访问、端到端加密邮件转发、区块链/去中心化存储数据共享等场景。

## 7. 工程决策

1. 使用 Java 17 record 简化不可变模型。
2. 使用 JCA `AES/GCM/NoPadding` 完成认证加密。
3. 使用 SHA-256 作为课程原型 KDF。
4. ECC 点运算采用无依赖教学实现，便于在无网络环境中运行；不声称具备生产级侧信道安全。
5. 业务层通过 `PreScheme` 抽象封装、解封装、代理转换；RSA/ECC 的 reKey 生成使用算法专用接口，避免接口污染。

## 8. 文件清单

核心实现：

```text
src/main/java/com/example/pre/crypto/rsa/RsaPreScheme.java
src/main/java/com/example/pre/crypto/ecc/EccPreScheme.java
src/main/java/com/example/pre/crypto/symmetric/AesGcm.java
src/main/java/com/example/pre/service/DataSecurityService.java
src/main/java/com/example/pre/service/AuthorizationService.java
```

演示与性能：

```text
src/main/java/com/example/pre/app/DemoApplication.java
src/main/java/com/example/pre/app/BenchmarkApplication.java
demo/README.md
demo/sample-data.txt
```

测试：

```text
src/test/java/com/example/pre/crypto
src/test/java/com/example/pre/scenario
src/test/java/com/example/pre/negative
src/test/java/com/example/pre/performance
```

## 9. 局限性

1. RSA-PRE 采用共同模数教学构造，不适合生产。
2. ECC-PRE 采用交互式教学构造，不抗合谋。
3. ECC 点运算不是常数时间实现，不具备侧信道安全承诺。
4. 内存仓储只用于 Demo，没有持久化、认证、访问策略引擎和撤销机制。

## 10. 结论

本项目完成了代理重加密在数据安全共享中的核心流程：数据加密、密钥封装、授权、代理转换、被授权人解密、未授权访问失败和篡改检测。RSA 与 ECC 两套方案可用于课程演示和性能对比，同时文档明确区分了教学原型与生产级 PRE 的差异。
