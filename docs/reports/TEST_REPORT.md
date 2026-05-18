# 测试报告：代理重加密 Java 实现

## 1. 测试环境

测试日期：2026-05-19

工作目录：

```text
/Users/chu/Desktop/Antigravity-Workspace/CourseProjects/proxy-re-enc
```

Java 环境：

```text
openjdk version "25.0.2" 2026-01-20
OpenJDK Runtime Environment Homebrew (build 25.0.2)
OpenJDK 64-Bit Server VM Homebrew (build 25.0.2, mixed mode, sharing)
javac 25.0.2
```

Maven 环境：

```text
Apache Maven 3.9.16
```

说明：本次 Maven 测试使用项目内本地仓库，命令为：

```bash
mvn -Dmaven.repo.local=target/m2 test
```

## 2. 总体验证结论

测试结论：通过。

Maven Surefire 汇总：

```text
Tests run: 12, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

同时已真实运行：

```bash
javac -d target/classes $(find src/main/java -name '*.java')
java -cp target/classes com.example.pre.app.DemoApplication
java -cp target/classes com.example.pre.app.BenchmarkApplication
```

生成文件：

```text
demo/output/demo-result.txt
docs/reports/performance-results.csv
target/surefire-reports/
```

## 3. JUnit 测试结果

| 测试类 | 用例数 | Failures | Errors | Skipped |
|---|---:|---:|---:|---:|
| `AesGcmTest` | 1 | 0 | 0 | 0 |
| `RsaPreSchemeTest` | 3 | 0 | 0 | 0 |
| `EccPreSchemeTest` | 3 | 0 | 0 | 0 |
| `TamperDetectionTest` | 1 | 0 | 0 | 0 |
| `UnauthorizedAccessTest` | 1 | 0 | 0 | 0 |
| `DataSharingScenarioTest` | 2 | 0 | 0 | 0 |
| `PreBenchmarkTest` | 1 | 0 | 0 | 0 |

合计：

```text
12 tests, 0 failures, 0 errors, 0 skipped
```

## 4. 覆盖内容

### 4.1 AES-GCM 测试

文件：

```text
src/test/java/com/example/pre/crypto/AesGcmTest.java
```

覆盖：

1. 正确密钥、nonce、AAD 可解密出原文。
2. 修改密文后认证失败。

### 4.2 RSA-PRE 测试

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

### 4.3 ECC-PRE 测试

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

### 4.4 场景测试

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
6. 审计日志包含 `KEYGEN`、`UPLOAD_ENCRYPTED`、`AUTHORIZE`、`RE_ENCRYPT`。

### 4.5 负向测试

文件：

```text
src/test/java/com/example/pre/negative/UnauthorizedAccessTest.java
src/test/java/com/example/pre/negative/TamperDetectionTest.java
```

覆盖：

1. 未授权用户不能解密原始数据包。
2. 修改 AES-GCM 内容密文后解密失败。

### 4.6 性能输出测试

文件：

```text
src/test/java/com/example/pre/performance/PreBenchmarkTest.java
```

覆盖：

1. `BenchmarkApplication` 可生成 CSV。
2. CSV 包含 RSA-PRE 和 ECC-PRE 结果。

## 5. Demo 运行结果

Demo 命令：

```bash
java -cp target/classes com.example.pre.app.DemoApplication
```

输出文件：

```text
demo/output/demo-result.txt
```

关键结果：

```text
=== RSA-PRE Scenario ===
Alice uploads encrypted file: success
Ciphertext differs from plaintext: true
Bob decrypts before authorization: failed
Proxy re-encrypts capsule: success
Bob decrypts after authorization: success
Charlie decrypts after Bob authorization: failed

=== ECC-PRE Scenario ===
Alice uploads encrypted file: success
Ciphertext differs from plaintext: true
Bob decrypts before authorization: failed
Proxy re-encrypts capsule: success
Bob decrypts after authorization: success
Charlie decrypts after Bob authorization: failed
```

## 6. 性能测试结果

性能测试命令：

```bash
java -cp target/classes com.example.pre.app.BenchmarkApplication
```

输出文件：

```text
docs/reports/performance-results.csv
```

本次结果：

```text
algorithm,stage,avg_ms,p50_ms,p95_ms,min_ms,max_ms,size_bytes
RSA-PRE,keygen,0.6831,0.6806,0.7710,0.5997,0.7710,0
RSA-PRE,encapsulate,0.5516,0.5392,0.6118,0.5133,0.6118,304
RSA-PRE,rekey,0.0020,0.0012,0.0089,0.0012,0.0089,0
RSA-PRE,reencrypt,1.7082,1.6888,1.8141,1.6802,1.8141,304
RSA-PRE,decapsulate,1.7837,1.7420,2.0123,1.7170,2.0123,32
ECC-PRE,keygen,2.5649,2.5715,2.6796,2.4193,2.6796,0
ECC-PRE,encapsulate,5.2895,5.2199,6.5697,4.8839,6.5697,113
ECC-PRE,rekey,0.0096,0.0076,0.0185,0.0068,0.0185,0
ECC-PRE,reencrypt,2.4783,2.4533,2.6254,2.3493,2.6254,113
ECC-PRE,decapsulate,2.6927,2.6445,3.0061,2.4763,3.0061,32
```

说明：当前 ECC 点运算是教学型 Java 实现，不是优化过的生产级曲线库，因此 ECC 性能结果主要用于课程原型内部对比，不代表成熟密码库性能。

## 7. 最终状态

| 项目 | 状态 |
|---|---|
| Java 源码编译 | 通过 |
| Maven JUnit 测试 | 通过 |
| RSA-PRE Demo | 通过 |
| ECC-PRE Demo | 通过 |
| 未授权访问验证 | 通过 |
| 篡改检测验证 | 通过 |
| 性能 CSV 生成 | 通过 |
| 技术报告 | 已生成 |
| 测试报告 | 已更新 |

