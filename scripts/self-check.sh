#!/usr/bin/env bash
# Evaluate this repository's published policies against this repository.
#
# `make test` proves the rules fire correctly against fixtures. It says nothing
# about whether the repo shipping those rules obeys them. Without this script
# the gap is invisible and permanent: someone adds `uses: actions/checkout@v5`
# to a workflow here, every fixture still passes, `conftest verify` is green,
# and a repository whose entire thesis is policy-as-code merges an unpinned
# action. That is the one failure this project cannot afford, so it is checked
# by the same engine and the same rule sources that consumers get.
#
# Two namespaces, because the two policy packages read two different kinds of
# document and neither can be pointed at the other's input:
#
#   github  the workflow YAML in .github/workflows/, read as workflows
#   repo    an inventory document generated from the working tree, which is
#           what policy/repo evaluates — a list of paths, not a manifest
#
# Three things this is deliberate about:
#
#   `--namespace` is mandatory. Conftest defaults to `main`, which holds no
#   rules here, so a missing flag reports zero findings on anything and the
#   gate reads as green. Same class of bug as the one rule-coverage.sh exists
#   to prevent: a check that cannot go red gets quoted as evidence.
#
#   `--data data/` is mandatory too, and fails the other way. GHA-002 and
#   GHA-003 comprehend over their allowlists, so an allowlist that never loaded
#   approves nothing and the run goes red. Dropping the flag is loud, which is
#   the correct direction for an allowlist to fail.
#
#   Both namespaces run before the script exits. `set -e` would stop at the
#   first failing namespace and hide the second, so the status is accumulated
#   instead — one run should report everything wrong with the repo, not the
#   first thing.
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

status=0

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
