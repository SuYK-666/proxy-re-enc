#!/usr/bin/env sh
set -eu

if command -v mdformat >/dev/null 2>&1; then
  mdformat README.md docs
  exit 0
fi

if command -v python >/dev/null 2>&1; then
  python -m mdformat README.md docs
  exit 0
fi

echo "mdformat is required. Install it with: python -m pip install mdformat" >&2
exit 1
