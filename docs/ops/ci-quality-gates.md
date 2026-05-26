# CI Quality Gates

`.github/workflows/backend-ci.yml` 在 Java 17 上执行：

1. `mvn --batch-mode verify`：JUnit、JaCoCo line threshold、SpotBugs High 检查及 CycloneDX SBOM。
1. `scripts/check-security-boundary.sh`：production 明文边界和 package verifier 存在性门禁。
1. `scripts/run-all-experiments.sh`：重跑 raw 与 summary 证据。
1. `check-doc-links.sh` 与 `check-performance-budget.sh`：验证交付文档集合、
	正确性及 5000 ms smoke budget。
1. 上传 Surefire、JaCoCo、SBOM 与实验 artifacts。

`pom.xml` 保留 OWASP Dependency Check 的 `CVSS >= 7` 配置；在有漏洞库
网络/缓存的发布流水线应执行 `mvn dependency-check:check`，发现高危漏洞时
禁止发布或提交带到期日的风险例外。

JaCoCo 统计业务/API/crypto/service 代码；由 `run-all-experiments` 直接执行并
输出 raw evidence 的命令型入口（experiment/demo/healthcheck runner）
不重复计入 JUnit 行覆盖分母。它们的可执行性由实验生成步骤和容器
healthcheck 证明。
