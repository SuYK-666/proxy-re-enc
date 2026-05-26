#!/usr/bin/env sh
set -eu

if command -v markdownlint-cli2 >/dev/null 2>&1; then
  markdownlint-cli2 --config .markdownlint.yml "README.md" "docs/**/*.md"
  exit 0
fi

npx --yes markdownlint-cli2 --config .markdownlint.yml "README.md" "docs/**/*.md"
