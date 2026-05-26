#!/usr/bin/env sh
set -eu

commit="$(git rev-parse --short HEAD)"
mvn -q -Drekeyshare.nonce.registry=target/experiment/test-aes-gcm-nonces.txt test
mvn -q -DskipTests compile
mvn -q -Dexec.mainClass=com.example.pre.app.BenchmarkApplication \
  -Drekeyshare.nonce.registry=target/experiment/aes-gcm-nonces.txt exec:java
mvn -q -Dexec.mainClass=com.example.pre.app.EvidenceExperimentApplication \
  -Drekeyshare.commit="$commit" exec:java
mvn -q -Dexec.mainClass=com.example.pre.app.ConcurrencyExperimentApplication \
  -Drekeyshare.nonce.registry=target/experiment/aes-gcm-nonces.txt -Drekeyshare.commit="$commit" exec:java
mvn -q -Dexec.mainClass=com.example.pre.app.ComplianceExperimentApplication \
  -Drekeyshare.commit="$commit" exec:java

printf '%s\n' "Raw evidence: docs/reports/raw/" "Summaries: docs/reports/summary/"
