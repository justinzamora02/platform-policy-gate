#!/usr/bin/env bash
# Evaluate this repository's published policies against this repository.
# See README § Self-enforcement for why, and for the two namespaces.
#
# A path matching no files is an error from Conftest and is left to fail. If
# .github/workflows/ is ever renamed or emptied, this must go red rather than
# congratulate the repo on having no violations.
set -euo pipefail

CONFTEST="${CONFTEST:-conftest}"

# Paths below are repo-relative so the output names files the way a reviewer
# refers to them, and so a run from a subdirectory checks the same tree.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The inventory is a build artifact of the current working tree, not a source
# file. Writing it to a temp dir rather than the repo root keeps it from ever
# being staged by an unlucky `git add -A`, and keeps this script from being the
# reason `git status` is dirty in the middle of a release.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

./scripts/repo-inventory.sh . >"$work/repo-inventory.json"

# Accumulated rather than `set -e`: one run should report everything wrong with
# the repo, not stop at the first failing namespace.
status=0

# `--namespace` is mandatory — Conftest defaults to `main`, which holds no rules
# here, so omitting it reports zero findings and the gate reads green.
# `--data data/` is mandatory the other way: GHA-002/003 comprehend over their
# allowlists, so an allowlist that never loaded approves nothing and goes red.
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
