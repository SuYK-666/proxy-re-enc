# 基于代理重加密的数据安全管理算法实现技术方案

## 1. 项目目标

本项目使用 Java 实现一个可演示、可验证、可性能对比的代理重加密数据安全管理系统。系统围绕“数据拥有者将加密数据托管到云端，并授权数据使用者在不暴露明文和原始私钥的情况下访问数据”的场景展开。

本阶段只完成技术方案设计。待方案确认后，再进入编码实现、测试验证、性能评估和实验报告整理。

### 1.1 核心交付物

1. Java 工程源码。
1. RSA 代理重加密算法原型。
1. ECC 代理重加密算法原型。
1. 基于混合加密的数据安全管理流程。
1. 典型数据共享场景演示。
1. 正确性测试、异常测试、性能对比测试。
1. 实验说明文档和运行说明。

### 1.2 设计原则

1. 明确区分“教学原型”和“生产级密码系统”。
1. 算法流程完整，便于解释代理重加密的密钥转换过程。
1. 数据加密采用混合加密：代理重加密只处理数据密钥封装，文件内容使用 AES-GCM 加密。
1. RSA 与 ECC 使用统一的业务抽象，便于横向对比。
1. 所有演示流程都能通过自动化测试验证。

## 2. 研究背景与应用场景

### 2.1 传统云数据共享的问题

在传统云计算系统中，用户通常将数据上传到云端，云端负责存储和访问控制。若数据以明文保存，云服务商或被入侵的云平台可能直接读取敏感信息。若数据由数据拥有者本地加密后上传，云端虽然无法读取明文，但后续共享会遇到以下问题：

1. 数据拥有者需要下载、解密、再使用接收者公钥重新加密，流程复杂。
1. 数据拥有者必须长期在线，授权效率低。
1. 每新增一个被授权人，就可能需要生成一份新的密文副本，存储成本高。
1. 如果直接把数据密钥发给被授权人，密钥泄露后难以控制风险。
1. 云端访问控制和密码学访问控制没有解耦，半可信云平台仍可能成为安全薄弱点。

### 2.2 代理重加密的作用

代理重加密允许数据拥有者提前生成从自己到被授权人的转换密钥，并交给半可信代理。代理可以把“由数据拥有者公钥加密的数据密钥密文”转换成“可由被授权人私钥解密的数据密钥密文”。代理只执行密文转换，不能得到明文数据密钥，也不能解密业务数据。

### 2.3 典型应用场景

本项目最终 Demo 采用“企业文档共享”作为主场景，同时在报告中补充医疗数据、邮件转发和区块链数据共享三个场景，用于说明 PRE 在不同系统中的实际价值。

#### 2.3.1 企业文档共享

传统方案痛点：

1. Alice 把合同、课程资料或项目文件加密上传云端后，若要共享给 Bob，通常需要下载明文、重新加密、再次上传。
1. 每个被授权人都保存一份独立文件密文，存储和同步成本较高。
1. 若直接把数据密钥发送给 Bob，密钥泄露后云端无法再提供密码学隔离。

PRE 解决方式：

1. 文件内容只加密一次，云端只保存一份文件密文。
1. Alice 只为 Bob 生成重加密密钥，代理只转换数据密钥胶囊。
1. Bob 使用自己的私钥恢复数据密钥，代理和云端都不接触文件明文。

局限性：

1. 授权撤销需要配合密钥轮换或版本化数据密钥。
1. 若被授权人已经获得明文，密码学机制无法阻止其离线复制。

#### 2.3.2 医疗数据委托访问

传统方案痛点：

1. 患者病历、检查报告长期保存在医院或云平台中，平台侧若持有明文会形成集中泄露风险。
1. 患者临时授权医生、保险机构或远程会诊专家访问数据时，若依赖人工导出和重新加密，效率低且审计困难。

PRE 解决方式：

1. 患者或数据管理方作为 Owner 上传加密病历。
1. 当医生 Bob 获得授权时，代理只转换病历数据密钥胶囊。
1. 平台可以记录“谁授权、谁转换、谁访问”，但不能读取病历明文。

局限性：

1. 医疗场景通常要求强身份认证、合规审计和细粒度撤销，课程原型只演示密码学核心流程。
1. 生产系统还需要密钥托管、硬件安全模块和合规访问策略。

#### 2.3.3 端到端加密邮件转发

传统方案痛点：

1. Alice 收到加密邮件后，如果要把邮件安全转发给 Bob，通常需要本地解密后再用 Bob 公钥重新加密。
1. 自动转发规则与端到端加密天然冲突，因为邮件服务器不应读取明文。

PRE 解决方式：

1. Alice 预先向邮件代理提供 Alice 到 Bob 的重加密密钥。
1. 邮件服务器在不解密邮件内容的前提下，把邮件密钥胶囊转换给 Bob。
1. Bob 用自己的私钥读取邮件，服务器仍然不知道邮件明文。

局限性：

1. 邮件元数据仍可能暴露通信关系。
1. 生产系统需要防止代理滥用长期重加密密钥。

#### 2.3.4 区块链或去中心化存储数据共享

传统方案痛点：

1. 链上或去中心化存储中的密文不可轻易修改，重新加密大文件成本高。
1. 智能合约适合记录授权状态，但不适合处理明文或大文件加密。

PRE 解决方式：

1. 数据密文保存在 IPFS、对象存储或链下数据库。
1. 链上只记录授权关系、数据哈希和访问策略。
1. 代理根据授权事件转换数据密钥胶囊，避免重新上传大文件。

局限性：

1. 链上授权撤销与链下密钥轮换需要一致性设计。
1. 代理节点的可用性和作恶检测需要额外机制。

### 2.4 PRE 理论分类

为了满足“深入剖析”的要求，报告中会明确讨论 PRE 的以下分类，并把本项目实现放入这些分类中。

1. 单向 PRE 与双向 PRE：单向 PRE 只允许 Alice 到 Bob 的转换，不能自动推出
  Bob 到 Alice 的转换；双向 PRE 则可以双向转换，但通常意味着更强的密钥关联和
  更高的安全风险。本项目 RSA 与 ECC 教学方案都按单向授权流程组织。
1. 单跳 PRE 与多跳 PRE：单跳 PRE 只允许密文转换一次；多跳 PRE 允许 A 到 B
  再到 C 的连续转换。本项目只实现单跳，避免多次转换带来的安全分析复杂度。
1. 交互式 PRE 与非交互式 PRE：非交互式方案中，Owner 只使用自己的私钥和
  Recipient 公钥生成转换密钥；交互式方案需要 Recipient 参与授权协议。
  RSA 教学方案接近非交互式；ECC 教学方案由于公式限制，需要把 Recipient
  的参与作为安全边界重点说明。
1. 单代理 PRE 与门限 PRE：单代理方案把转换能力交给一个代理；门限 PRE 将
  转换密钥拆成多个片段，需要多个代理共同完成转换。生产级 Umbral 类方案常
  采用门限思想，本项目实现单代理版本，报告中作为生产扩展讨论。
1. 代理透明性：代理透明性关注接收者是否能区分密文是否被代理转换过，以及
  代理是否能识别授权关系。本项目不实现代理透明性，只记录审计日志并用于
  课程演示。

## 3. 威胁模型与安全边界

### 3.1 参与方

1. 数据拥有者 Owner：生成原始密文和授权重加密密钥。
1. 数据使用者 Recipient：获得转换后的密文并解密数据。
1. 代理 Proxy：半可信，负责密文转换。
1. 云存储 Storage：保存密文数据和元数据。
1. 攻击者 Attacker：可能窃取云端密文、监听网络、尝试伪造授权。

### 3.2 安全目标

1. 云存储无法读取数据明文。
1. 代理仅凭重加密密钥和密文无法恢复明文。
1. 未被授权用户无法解密数据。
1. 被授权用户只能通过自己的私钥解密转换后的密文。
1. 系统可以记录授权、转换、解密等关键事件。

### 3.3 非目标与限制

1. 本项目不实现生产级密钥管理系统。
1. 本项目不实现分布式云存储。
1. RSA 方案采用教学型共同模数 RSA-PRE KEM，并加入共享指数因子以避免最直观的共同模数攻击，但仍不声称具备生产级 CCA 安全。
1. ECC 方案采用教学型椭圆曲线 ElGamal 风格交互式 PRE KEM，不要求 Alice 直接知道 Bob 私钥，但需要 Bob 参与生成转换材料；该方案不声称抵抗代理与被授权人合谋。
1. 若要生产使用，应改用经过安全证明和工程审计的成熟代理重加密方案，例如 Umbral 类方案或基于双线性配对的 PRE 方案。

## 4. 总体架构

### 4.1 架构分层

```text
application
  DemoApp / CliApp / ScenarioRunner

service
  UserService
  DataSecurityService
  AuthorizationService
  BenchmarkService

crypto
  PreScheme
  RsaPreScheme
  RsaReKeyGenerator
  EccPreScheme
  EccInteractiveReKeyGenerator
  AesGcmCipher
  KdfUtil
  SecureRandomUtil

model
  UserKeyPair
  EncryptedDataPackage
  ReEncryptionKey
  ReEncryptedPackage
  AuditEvent

storage
  InMemoryUserRepository
  InMemoryDataRepository
  InMemoryAuditRepository

test
  correctness
  negative
  performance
```

### 4.2 统一算法接口

业务层只统一“封装、解封装、代理转换”等通用动作，不强行统一“重加密密钥生成”
签名。原因是 RSA 与 ECC 的 reKey 生成假设不同：RSA 教学方案可由 Owner 根据
自己的私钥和 Recipient 公钥生成；ECC 教学方案需要 Recipient 参与生成转换材料。
把二者硬塞进同一个方法会污染接口，并掩盖 ECC 方案的安全边界。

```java
public interface PreScheme {
    String name();

    UserKeyPair generateKeyPair(String userId);

    EncryptedKeyCapsule encapsulate(byte[] dataKey, PublicKeyMaterial ownerPublicKey);

    byte[] decapsulate(EncryptedKeyCapsule capsule, PrivateKeyMaterial privateKey);

    EncryptedKeyCapsule reEncrypt(EncryptedKeyCapsule originalCapsule, ReEncryptionKey reKey);
}
```

算法专用 reKey 生成接口：

```java
public interface RsaReKeyGenerator {
    ReEncryptionKey generateReEncryptionKey(
            PrivateKeyMaterial ownerPrivateKey,
            PublicKeyMaterial recipientPublicKey
    );
}

public interface EccInteractiveReKeyGenerator {
    RecipientReKeyShare createRecipientShare(
            PrivateKeyMaterial recipientPrivateKey,
            ReKeySessionContext context
    );

    ReEncryptionKey generateReEncryptionKey(
            PrivateKeyMaterial ownerPrivateKey,
            PublicKeyMaterial recipientPublicKey,
            RecipientReKeyShare recipientShare,
            ReKeySessionContext context
    );
}
```

说明：`RecipientReKeyShare` 是 ECC 教学方案的显式交互材料，不能在报告中描述成
“Bob 私钥交给 Alice”。实现时会把它标记为敏感材料，并在安全分析中说明它仍然
不足以达到生产级抗合谋安全。生产级方向采用 Umbral 类或配对型 PRE，不使用
该教学接口。

## 5. 数据安全管理流程

### 5.1 混合加密流程

业务数据不直接使用 RSA 或 ECC 加密，而是采用混合加密：

1. 生成随机数据密钥 DEK。
1. 使用 AES-256-GCM 加密文件内容。
1. 使用 PRE KEM 将 DEK 封装给数据拥有者。
1. 上传文件密文、AES-GCM nonce、认证标签、PRE 胶囊和元数据。
1. 授权时只转换 PRE 胶囊，不重新加密文件内容。
1. 被授权人解封装 DEK，再用 DEK 解密文件密文。

### 5.2 数据包结构

```text
EncryptedDataPackage
  dataId
  ownerId
  algorithm: RSA_PRE or ECC_PRE
  encryptedContent
  aesNonce
  aad
  originalCapsule
  createdAt
```

```text
ReEncryptedPackage
  dataId
  ownerId
  recipientId
  algorithm
  encryptedContent
  aesNonce
  aad
  reEncryptedCapsule
  authorizedAt
```

### 5.3 审计事件

系统会记录以下事件：

1. 用户密钥生成。
1. 数据加密上传。
1. 授权关系创建。
1. 代理重加密执行。
1. 被授权用户解密成功或失败。

## 6. RSA 代理重加密方案

### 6.1 方案定位

RSA 方案用于教学演示代理重加密中的“指数转换”思想。该方案要求系统初始化阶段生成共同 RSA 模数 N 和欧拉函数 phi(N)，然后为每个用户选择不同的公私钥指数。

该方案便于理解和实现，但存在共同模数、密钥托管、抗合谋能力弱、不能直接使用 OAEP 等限制。因此，文档和报告中必须明确它是课程实验原型。

为了避免最直观的共同模数攻击，本项目不会为不同用户选择互素的公开指数，而是引入一个系统级共享指数因子 h：

```text
e_i = h * t_i
gcd(e_i, phi) = 1
gcd(t_i, phi) = 1
```

如果朴素地让 Alice 和 Bob 使用同一个 N，并且 `gcd(e_A, e_B) = 1`，攻击者一旦同时获得：

```text
c_A = s^{e_A} mod N
c_B = s^{e_B} mod N
```

就可以通过扩展欧几里得算法找到整数 u、v，使：

```text
u * e_A + v * e_B = 1
```

进而恢复：

```text
s = c_A^u * c_B^v mod N
```

这就是共同模数攻击。由于代理在重加密过程中可能同时看到原始胶囊和转换后胶囊，
若不处理该问题，代理就能恢复 KEM 随机数 s，进而恢复数据密钥。因此，
本项目实验实现要求所有用户公开指数共享同一个大因子 h，使攻击者最多由上述方法
恢复 `s^h`，不能直接得到 s。

该处理只能避免课程 Demo 中的直接漏洞，不等价于生产级安全证明。共同模数 RSA-PRE 仍然只作为教学方案使用。

### 6.2 密钥生成

系统公共参数：

```text
N = p * q
phi = (p - 1) * (q - 1)
选择共享指数因子 h，使 gcd(h, phi) = 1
```

用户 i 的密钥：

```text
选择 t_i，使 gcd(t_i, phi) = 1
e_i = h * t_i
确保 gcd(e_i, phi) = 1
d_i = e_i^{-1} mod phi
公钥 pk_i = (N, e_i)
私钥 sk_i = (N, d_i)
```

### 6.3 封装数据密钥

为了避免直接把任意字节作为 RSA 明文，RSA-PRE 作为 KEM 使用：

```text
随机选择 s in Z_N*
c_A = s^{e_A} mod N
kek = SHA-256("RSA-PRE-KEM" || s)
wrappedDEK = AES-GCM(kek, DEK)
capsule_A = (c_A, wrappedDEK, nonce, tag)
```

### 6.4 数据拥有者解封装

```text
s = c_A^{d_A} mod N
kek = SHA-256("RSA-PRE-KEM" || s)
DEK = AES-GCM-Decrypt(kek, wrappedDEK)
```

### 6.5 生成重加密密钥

Alice 授权 Bob：

```text
rk_A_to_B = d_A * e_B mod phi
```

### 6.6 代理重加密

代理输入 Alice 的胶囊和转换密钥：

```text
c_B = c_A^{rk_A_to_B} mod N
```

正确性：

```text
c_B = (s^{e_A})^{d_A * e_B}
    = s^{e_A * d_A * e_B}
    = s^{e_B} mod N
```

输出：

```text
capsule_B = (c_B, wrappedDEK, nonce, tag)
```

### 6.7 Bob 解封装

```text
s = c_B^{d_B} mod N
  = (s^{e_B})^{d_B}
  = s mod N
kek = SHA-256("RSA-PRE-KEM" || s)
DEK = AES-GCM-Decrypt(kek, wrappedDEK)
```

### 6.8 RSA 实现要点

1. 使用 BigInteger 处理模幂和模逆。
1. 默认 RSA 模数长度建议为 2048 位，可扩展到 3072 位。
1. 生成系统级共享指数因子 h，并保证所有用户公钥指数都含有 h。
1. 测试中显式验证 `gcd(e_A, e_B) = h` 或至少大于 1，避免朴素共同模数攻击。
1. 随机 s 必须满足 1 < s < N 且 gcd(s, N) = 1。
1. 所有字节编码使用固定长度无符号大端格式。
1. 性能统计记录 keygen、encapsulate、rekey、reencrypt、decapsulate 五个阶段。

## 7. ECC 代理重加密方案

### 7.1 方案定位

ECC 方案采用椭圆曲线 ElGamal 风格 KEM。它通过椭圆曲线点乘实现胶囊转换，展示 ECC 在密钥长度和执行效率上的优势。

与 RSA 教学方案不同，普通椭圆曲线群中仅依靠 Owner 私钥和 Recipient 公钥，很难用一个简单公式构造出安全、非交互、抗合谋的 PRE。若强行使用：

```text
rk_A_to_B = x_A * x_B^{-1} mod n
```

就会引入 Recipient 私钥相关材料，并带来明显合谋风险。因此本项目采用“双层叙述”：

1. 课程实现层：实现一个 ECC-ElGamal 教学型交互式 PRE KEM，用于展示点乘转换、正确性验证和性能对比。该方案需要 Bob 参与生成转换材料，且不声称生产级安全。
1. 报告分析层：正式说明该教学方案的缺陷，并给出生产级方向，例如 Umbral 类门限 PRE 或基于双线性配对的 PRE。生产级方向要求 reKey 生成只依赖 Owner 私钥和 Recipient 公钥，不能要求 Recipient 私钥离开持有人。

默认曲线选择 secp256r1，也称 P-256。原始决策优先使用 Bouncy Castle 提供的椭圆曲线点运算，避免自研点加、点倍加和标量乘带来的边界条件与侧信道风险。考虑到当前课程运行环境可能无法下载依赖，最终实现采用无外部依赖的 P-256 教学型点运算，并在报告中明确它不适合生产。

### 7.2 曲线参数

```text
E: y^2 = x^3 + ax + b mod p
基点 G
阶 n
用户私钥 x_i in [1, n - 1]
用户公钥 P_i = x_i * G
```

### 7.3 封装数据密钥

Alice 的公钥为：

```text
P_A = x_A * G
```

封装流程：

```text
随机选择 r in [1, n - 1]
C1 = r * G
S_A = r * P_A = r * x_A * G
kek = SHA-256("ECC-PRE-KEM" || encode(S_A))
wrappedDEK = AES-GCM(kek, DEK)
capsule_A = (C1, wrappedDEK, nonce, tag)
```

### 7.4 Alice 解封装

```text
S_A = x_A * C1
kek = SHA-256("ECC-PRE-KEM" || encode(S_A))
DEK = AES-GCM-Decrypt(kek, wrappedDEK)
```

### 7.5 生成重加密密钥

为了让 Bob 对转换后的点执行私钥点乘后得到同一个共享点，教学公式为：

```text
rk_A_to_B = x_A * x_B^{-1} mod n
```

其数学正确性清晰，但安全边界必须写清楚：

1. Alice 不应该直接知道 Bob 的私钥 x_B。
1. 课程实现中，Bob 通过本地方法参与授权会话，生成转换所需的敏感交互材料；代码接口不再把 `recipientPrivateKey` 放进通用 `PreScheme`。
1. 即使不直接传递 Bob 私钥，最终转换因子在数学上仍与 `x_A * x_B^{-1}` 等价。
1. 若代理拿到 `rk_A_to_B` 后与 Bob 合谋，Bob 可以结合自己的 x_B 推出 Alice 的 x_A。
1. 因此该 ECC 方案只能作为“交互式、非抗合谋”的教学型 PRE，不能作为生产级方案。

报告中会把该点作为重点分析：普通 ECC-ElGamal 风格 PRE 虽然容易展示点乘转换，但若要达到真实系统中的“Owner 单方授权、Recipient 私钥不外泄、代理和 Recipient 合谋也不能恢复 Owner 私钥”，需要采用 Umbral 类或配对型 PRE，而不是这个简化公式。

### 7.6 代理重加密

代理将胶囊中的 C1 转换为：

```text
C1' = rk_A_to_B * C1
    = (x_A * x_B^{-1}) * r * G
```

输出：

```text
capsule_B = (C1', wrappedDEK, nonce, tag)
```

代理不能计算：

```text
S_A = x_A * r * G
```

因为代理不知道 x_B，只有 Bob 能通过自己的私钥恢复共享点。

### 7.7 Bob 解封装

```text
S_B = x_B * C1'
    = x_B * (x_A * x_B^{-1}) * r * G
    = x_A * r * G
    = S_A
kek = SHA-256("ECC-PRE-KEM" || encode(S_B))
DEK = AES-GCM-Decrypt(kek, wrappedDEK)
```

### 7.8 ECC 实现要点

1. 当前实现使用无外部依赖的 P-256 教学型点加、点倍加、标量乘。
1. 若部署环境允许引入 Bouncy Castle，后续可替换底层点运算实现。
1. 验证输入点是否在曲线上，拒绝无穷远点作为外部输入。
1. 标量运算统一 mod n。
1. 点编码使用未压缩 SEC1 格式：0x04 || x || y。
1. KDF 输入使用完整点编码，而不是只使用 x 坐标。
1. 不把教学型点运算描述为常数时间实现，不声称具备侧信道安全。
1. 性能统计记录 keygen、encapsulate、rekey、reencrypt、decapsulate 五个阶段。

## 8. Java 工程规划

### 8.1 技术栈

1. Java 17。
1. Maven。
1. JUnit 5。
1. Java Cryptography Architecture。
1. AES/GCM/NoPadding。
1. SHA-256 或 HKDF-SHA256。
1. 可选：Bouncy Castle，用于替换教学型 ECC 点运算。
1. 可选：JMH，用于更严谨的性能测试。若课程环境不方便引入依赖，则实现轻量级基准测试器。

### 8.2 包结构

```text
src/main/java/com/example/pre
  app
    DemoApplication.java
    CliApplication.java
  crypto
    PreScheme.java
    rsa/RsaPreScheme.java
    rsa/RsaCommonModulusParameters.java
    ecc/EccPreScheme.java
    ecc/EccInteractiveReKeyGenerator.java
    ecc/P256Curve.java
    ecc/ECPoint.java
    symmetric/AesGcm.java
    kdf/Kdf.java
  model
    User.java
    UserKeyPair.java
    EncryptedDataPackage.java
    EncryptedKeyCapsule.java
    ReEncryptionKey.java
    ReEncryptedPackage.java
    AuditEvent.java
  service
    UserService.java
    DataSecurityService.java
    AuthorizationService.java
    ProxyReEncryptionService.java
    BenchmarkService.java
  storage
    UserRepository.java
    DataRepository.java
    AuditRepository.java
    InMemory*.java
  util
    Bytes.java
    Stopwatch.java
    JsonSupport.java
```

### 8.3 测试结构

```text
src/test/java/com/example/pre
  crypto
    RsaPreSchemeTest.java
    EccPreSchemeTest.java
    AesGcmTest.java
  scenario
    DataSharingScenarioTest.java
  negative
    UnauthorizedAccessTest.java
    TamperDetectionTest.java
  performance
    PreBenchmarkTest.java
```

## 9. 正确性与有效性验证

### 9.1 正确性测试

对 RSA 和 ECC 分别验证：

1. Owner 能解密自己加密的数据。
1. Recipient 不能直接解密 Owner 的原始胶囊。
1. Proxy 使用正确 reKey 后，Recipient 能解密转换后的数据。
1. Proxy 不能仅凭密文和 reKey 得到 DEK。
1. 其他未授权用户不能解密转换后的数据。
1. 同一文件内容在加密后密文不等于明文。
1. 多次加密同一明文得到不同密文。
1. RSA 参数测试验证 `gcd(e_A, e_B) > 1`，避免朴素共同模数攻击条件成立。
1. ECC 接口测试验证通用 `PreScheme` 不接收 Recipient 私钥，交互材料只出现在 ECC 专用授权流程中。

### 9.2 篡改检测

1. 修改 AES-GCM 密文，解密应失败。
1. 修改 AES-GCM nonce，解密应失败。
1. 修改 PRE 胶囊，解封装应失败或得到不可通过认证的数据密钥。
1. 使用错误 recipient 私钥，解密应失败。

### 9.3 场景验证

演示脚本包含：

```text
1. 创建 Alice、Bob、Charlie。
2. Alice 上传一段敏感文本或文件。
3. Bob 未授权访问失败。
4. Alice 授权 Bob。
5. Proxy 执行重加密。
6. Bob 解密成功。
7. Charlie 访问失败。
8. 输出审计日志。
9. 对 RSA 和 ECC 重复同一流程。
```

## 10. 性能对比方案

### 10.1 指标

1. 密钥生成耗时。
1. 数据密钥封装耗时。
1. 重加密密钥生成耗时。
1. 代理重加密耗时。
1. 被授权人解封装耗时。
1. 文件 AES-GCM 加解密耗时。
1. 密钥、胶囊、重加密密钥的序列化大小。

### 10.2 测试规模

建议测试以下文件大小：

1. 1 KB。
1. 10 KB。
1. 100 KB。
1. 1 MB。
1. 10 MB。

代理重加密本身只转换数据密钥胶囊，因此文件大小主要影响 AES-GCM，不应显著影响 PRE 过程。报告中要把“文件加密耗时”和“PRE 胶囊转换耗时”分开展示。

### 10.3 重复次数

每个算法和每个阶段执行：

```text
warmup: 100 次
measurement: 1000 次
```

输出：

1. 平均值。
1. P50。
1. P95。
1. 最小值。
1. 最大值。

### 10.4 预期结论

1. RSA 2048 位模幂计算成本较高，密文胶囊较大。
1. ECC P-256 私钥和公钥尺寸较小，点乘性能通常较好。
1. AES-GCM 文件加密耗时随文件大小线性增长。
1. PRE 重加密耗时与文件大小无关，体现混合加密优势。

## 11. 实施里程碑

### 阶段 1：项目骨架

1. 创建 Maven 工程。
1. 配置 Java 17、JUnit 5。
1. 建立 model、crypto、service、storage 包。
1. 建立统一异常类型和工具类。

### 阶段 2：通用数据安全层

1. 实现 AES-GCM。
1. 实现 KDF。
1. 实现数据包模型。
1. 实现内存仓储和审计日志。

### 阶段 3：RSA-PRE

1. 实现共同模数参数生成。
1. 实现共享指数因子 h。
1. 实现用户指数密钥生成。
1. 实现封装、解封装、reKey 生成和重加密。
1. 完成 RSA 正确性、异常测试和共同模数攻击规避测试。

### 阶段 4：ECC-PRE

1. 实现无外部依赖的 P-256 教学型点运算。
1. 实现点编码和点合法性校验。
1. 实现 ECC 封装、解封装、交互式 reKey 生成和重加密。
1. 完成 ECC 正确性、异常测试和抗合谋限制说明。

### 阶段 5：业务场景

1. 实现用户创建。
1. 实现数据上传加密。
1. 实现授权。
1. 实现代理重加密。
1. 实现被授权人读取。
1. 实现 DemoApplication 输出完整流程。

### 阶段 6：性能评估

1. 实现 BenchmarkService。
1. 采集 RSA 和 ECC 指标。
1. 输出 Markdown 或 CSV 结果。
1. 整理性能对比结论。

### 阶段 7：报告与验收

1. 编写 README。
1. 编写算法说明。
1. 编写运行说明。
1. 整理实验结果表。
1. 给出安全限制说明。

## 12. 风险与应对

### 12.1 RSA 共同模数风险

风险：共同模数 RSA 不是生产推荐做法，课程实现若不说明会产生安全误导。尤其是当不同用户的公开指数互素时，攻击者若同时得到同一 KEM 随机数 s 的两个密文：

```text
c_A = s^{e_A} mod N
c_B = s^{e_B} mod N
```

且 `gcd(e_A, e_B) = 1`，就可以用扩展欧几里得算法恢复 s。这会让代理在看到原始胶囊和转换后胶囊时直接恢复数据密钥，破坏 PRE 的基本安全目标。

应对：

1. 实验实现中为所有公开指数加入共享大因子 h，避免最简单的互素指数共同模数攻击。
1. 测试中加入检查，确保 Alice 和 Bob 的 `gcd(e_A, e_B)` 不为 1。
1. 在代码注释、README 和报告中明确标记为教学原型，并解释为什么真实系统不应直接采用共同模数 RSA-PRE。
1. 报告中将该攻击作为“为什么需要成熟 PRE 协议”的核心论据之一。

### 12.2 ECC 教学方案抗合谋不足

风险：ECC 教学公式 `rk_A_to_B = x_A * x_B^{-1} mod n` 清晰但脆弱。代理和 Bob
若合谋，Bob 可以从 rk 和自己的 x_B 恢复 Alice 私钥 x_A。同时，若实现时把 Bob
私钥或等价逆元材料交给 Alice，也违背私钥不离开持有人的基本原则。

应对：

1. 接口层不再把 `recipientPrivateKey` 放进统一 `PreScheme`。
1. ECC reKey 生成被定义为教学型交互式授权会话，由 Bob 本地参与生成敏感转换材料。
1. 报告中明确说明该方案不抗代理与 Recipient 合谋。
1. 把 Umbral 类门限 PRE 和基于双线性配对的 PRE 作为生产级替代方向说明。

### 12.3 椭圆曲线点运算实现复杂

风险：手写点运算容易出现边界条件错误，也容易因为条件分支、异常点处理和标量乘
算法暴露时序侧信道。课程实现若完全自研 ECC 底层，评审者可能质疑实现可靠性。

应对：

1. 当前实现启用教学型 P-256 点运算，保证无外部依赖可运行。
1. 若课程环境允许依赖，后续可引入 Bouncy Castle 处理 P-256 点运算。
1. 增加曲线点合法性测试。
1. 用已知基点阶性质测试 `n * G = O`。
1. 测试 `a * (b * G) = b * (a * G)`。
1. 明确声明教学型点运算不具备生产级侧信道安全。

### 12.4 性能测试波动

风险：JVM 预热、GC 和系统负载会影响结果。

应对：

1. 加入 warmup。
1. 每项执行多轮。
1. 输出多分位统计。
1. 报告中说明硬件和 JDK 版本。

## 13. 建议的最终演示输出

命令：

```bash
mvn test
mvn exec:java -Dexec.mainClass=com.example.pre.app.DemoApplication
mvn exec:java -Dexec.mainClass=com.example.pre.app.BenchmarkApplication
```

Demo 输出示例：

```text
=== RSA-PRE Scenario ===
Alice uploads encrypted file: success
Bob decrypts before authorization: failed
Proxy re-encrypts capsule: success
Bob decrypts after authorization: success
Charlie decrypts after Bob authorization: failed

=== ECC-PRE Scenario ===
Alice uploads encrypted file: success
Bob decrypts before authorization: failed
Proxy re-encrypts capsule: success
Bob decrypts after authorization: success
Charlie decrypts after Bob authorization: failed
```

Benchmark 输出示例：

```text
algorithm,stage,avg_ms,p50_ms,p95_ms,min_ms,max_ms,size_bytes
RSA_PRE,keygen,...
RSA_PRE,encapsulate,...
RSA_PRE,rekey,...
RSA_PRE,reencrypt,...
RSA_PRE,decapsulate,...
ECC_PRE,keygen,...
ECC_PRE,encapsulate,...
ECC_PRE,rekey,...
ECC_PRE,reencrypt,...
ECC_PRE,decapsulate,...
```

## 14. 待确认事项

以下事项已经按课程实现优先级做出默认决策，除非后续明确要求变更：

1. RSA 与 ECC 都采用教学型 PRE 原型，但报告中必须明确安全限制。
1. 使用 Maven 作为构建工具。
1. 先实现固定场景 Demo，不做复杂交互式菜单。
1. ECC 当前采用教学型 P-256 点运算；若课程环境允许依赖，可切换到 Bouncy Castle。
1. 性能测试先使用内置轻量 benchmark，不强依赖 JMH。
1. 数据示例同时支持文本和本地文件，加分点优先保留。

## 15. 推荐实施决策

建议采用以下默认决策：

1. Java 17 + Maven + JUnit 5。
1. 默认实现固定场景 Demo，同时保留简单 CLI 扩展空间。
1. RSA-PRE 使用 2048 位共同模数教学方案，并为公开指数加入共享大因子 h，避免最简单的共同模数攻击。
1. ECC-PRE 使用 P-256 交互式教学方案，当前使用无依赖教学型点运算，报告中明确它不抗合谋。
1. 文件内容统一使用 AES-256-GCM。
1. 性能测试先实现内置轻量 benchmark，避免额外依赖影响课程环境。
1. README 中单独加入“安全限制与生产替代方案”章节。
