# E13 Threshold Prototype

- Commit: `9189d85`
- JDK: `22.0.2`
- OS: `Windows 11 10.0`
- Generated: `2026-05-26T11:45:39.016117700Z`

Signed-share aggregation was measured for 30 successful samples each of t=2,n=3 and t=3,n=5, plus below-threshold rejection cases. This remains an experimental re-key orchestration prototype, not a reviewed threshold PRE construction.

Raw data: `../raw/e13-threshold-results.csv`

Result: **PASS** (signed shares verify; fewer than t fail; t or more recover).
