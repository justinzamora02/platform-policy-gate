#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

for command in make opa conftest jq; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "setup: missing required command: $command" >&2
		exit 1
	fi
done

git config core.hooksPath .githooks
echo "setup: enabled .githooks for this clone"
make check
