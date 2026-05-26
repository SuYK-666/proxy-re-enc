# E11 API Robustness

- Commit: `a85e36f`
- JDK: `25.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T06:34:57.330477900Z`

Malformed JSON, unsupported content type, oversized body and hostile
unauthenticated path input were handled as client failures without an HTTP 5xx
response.

Raw data: `../raw/e11-api-robustness-results.json`

Result: **PASS**.
