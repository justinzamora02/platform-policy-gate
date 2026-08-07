#!/usr/bin/env bash
# Evaluate this repository's published policies against this repository.
set -euo pipefail

CONFTEST="${CONFTEST:-conftest}"

# Repo-relative paths, so a run from a subdirectory checks the same tree.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

./scripts/check-workflow-hardening.sh

# The inventory is an artifact of the working tree, not a source file, so it
# never lands where `git add -A` could stage it.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

./scripts/repo-inventory.sh . >"$work/repo-inventory.json"

# Accumulated rather than `set -e`, so one run reports everything wrong with the
# repo instead of stopping at the first failing namespace.
status=0

# `--namespace` and `--data data/` are both mandatory: Conftest defaults to the
# empty `main` namespace, and the allowlist rules fail closed without their data.
echo "self-check: github namespace over .github/workflows/"
"$CONFTEST" test \
	--policy policy \
	--data data/ \
	--namespace github \
	.github/workflows/ || status=1

echo
echo "self-check: repo namespace over the working-tree inventory"
"$CONFTEST" test \
	--policy policy \
	--data data/ \
	--namespace repo \
	"$work/repo-inventory.json" || status=1

echo

if [[ "$status" -ne 0 ]]; then
	echo "self-check: this repository violates its own published policies (see above)" >&2
	exit 1
fi

echo "self-check: this repository passes its own published policies"
