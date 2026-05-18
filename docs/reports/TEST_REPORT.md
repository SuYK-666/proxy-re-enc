# 测试报告：代理重加密 Java 实现

## 1. 测试环境

当前执行环境：

```text
工作目录: /Users/chu/Desktop/Antigravity-Workspace/CourseProjects/proxy-re-enc
系统 shell: zsh
```

本机验证阻塞：

```text
mvn test
=> zsh:1: command not found: mvn

java -version
=> The operation couldn’t be completed. Unable to locate a Java Runtime.

javac -version
=> The operation couldn’t be completed. Unable to locate a Java Runtime.
```

结论：当前机器缺少 Java Runtime/JDK 和 Maven，因此无法在本机实际编译运行 Java 测试。源码、测试用例、Demo 和 Benchmark 已完整生成；在安装 Java 17 和 Maven 后可直接执行。

## 2. 建议执行命令

```bash
mvn test
mvn exec:java -Dexec.mainClass=com.example.pre.app.DemoApplication
mvn exec:java -Dexec.mainClass=com.example.pre.app.BenchmarkApplication
```

预期输出文件：

```text
demo/output/demo-result.txt
docs/reports/performance-results.csv
```

## 3. 已编写测试用例

### 3.1 AES-GCM 测试

文件：

```text
src/test/java/com/example/pre/crypto/AesGcmTest.java
```

覆盖：

1. 正确密钥、nonce、AAD 可解密出原文。
2. 修改密文后认证失败。

### 3.2 RSA-PRE 测试

文件：

```text
src/test/java/com/example/pre/crypto/RsaPreSchemeTest.java
```

覆盖：

1. Alice 能解封装自己封装的数据密钥。
2. Bob 未授权不能直接解封装 Alice 胶囊。
3. Proxy 使用 reKey 转换后 Bob 能解封装。
4. RSA 用户公开指数存在非平凡公共因子，避免最直接共同模数攻击条件。
5. 篡改 RSA 胶囊后解封装失败。

### 3.3 ECC-PRE 测试

文件：

```text
src/test/java/com/example/pre/crypto/EccPreSchemeTest.java
```

覆盖：

1. Alice 能解封装自己封装的数据密钥。
2. Bob 未授权不能直接解封装 Alice 胶囊。
3. 交互式 reKey 生成后 Bob 能解封装转换胶囊。
4. P-256 基点在曲线上。
5. `n * G` 得到无穷远点。
6. 篡改 ECC 点编码后解封装失败。

### 3.4 场景测试

文件：

```text
src/test/java/com/example/pre/scenario/DataSharingScenarioTest.java
```

覆盖：

1. RSA-PRE 端到端数据共享。
2. ECC-PRE 端到端数据共享。
3. Alice 上传加密数据。
4. Bob 授权前失败、授权后成功。
5. Charlie 未授权失败。
6. 审计日志包含 KEYGEN、UPLOAD、AUTHORIZE、RE_ENCRYPT。

### 3.5 负向测试

文件：

```text
src/test/java/com/example/pre/negative/UnauthorizedAccessTest.java
src/test/java/com/example/pre/negative/TamperDetectionTest.java
```

覆盖：

1. 未授权用户不能解密原始数据包。
2. 修改 AES-GCM 内容密文后解密失败。

### 3.6 性能输出测试

文件：

```text
src/test/java/com/example/pre/performance/PreBenchmarkTest.java
```

覆盖：

1. BenchmarkApplication 可生成 CSV。
2. CSV 包含 RSA-PRE 和 ECC-PRE 结果。

## 4. Demo 验收点

DemoApplication 预期展示：

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

## 5. 当前状态

| 项目 | 状态 |
|---|---|
| Java 源码实现 | 已完成 |
| Demo 文件夹 | 已创建 |
| JUnit 测试用例 | 已完成 |
| 性能测试入口 | 已完成 |
| 技术报告 | 已完成 |
| 本机实际编译 | 阻塞：缺少 JDK |
| 本机 Maven 测试 | 阻塞：缺少 Maven |

## 6. 后续验证建议

安装 Java 17 和 Maven 后，优先执行：

```bash
mvn test
```

若测试通过，再执行：

```bash
mvn exec:java -Dexec.mainClass=com.example.pre.app.DemoApplication
mvn exec:java -Dexec.mainClass=com.example.pre.app.BenchmarkApplication
```

然后检查：

```text
demo/output/demo-result.txt
docs/reports/performance-results.csv
```
