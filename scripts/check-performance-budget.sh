#!/usr/bin/env sh
set -eu
awk -F, 'NR > 1 && ($15 != "true" || $12 + 0 > 5000) { bad=1 } END { exit bad }' docs/reports/raw/e02-algorithm-benchmark.csv
printf '%s\n' 'Performance smoke budget passed; detailed percentiles are recorded in the summary report.'
