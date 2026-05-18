# Demo

运行命令：

```bash
mvn test
mvn exec:java -Dexec.mainClass=com.example.pre.app.DemoApplication
mvn exec:java -Dexec.mainClass=com.example.pre.app.BenchmarkApplication
```

输出文件：

```text
demo/output/demo-result.txt
docs/reports/performance-results.csv
```

Demo 会分别执行 RSA-PRE 和 ECC-PRE 场景：

1. 创建 Alice、Bob、Charlie。
2. Alice 加密上传数据。
3. Bob 未授权直接解密失败。
4. Alice 授权 Bob。
5. Proxy 执行重加密。
6. Bob 解密成功。
7. Charlie 解密失败。
8. 输出审计日志。
