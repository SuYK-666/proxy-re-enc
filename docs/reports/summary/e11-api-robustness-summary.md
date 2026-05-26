# E11 API Robustness

- Commit: `9189d85`
- JDK: `22.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T11:46:30.211854600Z`

Malformed JSON, unsupported content type, oversized body and hostile unauthenticated path input were handled as client failures without an HTTP 5xx response.

Raw data: `../raw/e11-api-robustness-results.json`

Result: **PASS**.
