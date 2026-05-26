$ErrorActionPreference = 'Stop'
$csv = Import-Csv 'docs/reports/raw/e02-algorithm-benchmark.csv'
if (($csv | Where-Object { $_.success -ne 'true' }).Count -gt 0) {
  throw 'Benchmark contains failed correctness samples.'
}
$tooSlow = $csv | Where-Object { [double]$_.totalMs -gt 5000 }
if ($tooSlow.Count -gt 0) {
  throw 'Benchmark contains a total latency sample over the 5000ms smoke budget.'
}
Write-Host 'Performance smoke budget passed; detailed p50/p95/p99 remain in the summary report.'
