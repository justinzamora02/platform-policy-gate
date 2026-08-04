#!/usr/bin/env bash
# Fail the build when a policy can emit a rule ID that no test ever trips.
#
# The obvious implementation greps the rule IDs out of policy/ and greps them
# out of policy/*_test.rego, then compares. It reports full coverage forever:
# every ID a policy emits is also written in the test that names it, a `#
# K8S-004:` comment counts the same as a rule, and an assertion that was
# deleted down to a fixture that no longer trips anything still leaves the
# string sitting in the file. A gate that cannot go red is worse than no gate,
# because it gets quoted as evidence.
#
# So the two halves are measured with two different tools, and neither can be
# satisfied by text that merely exists:
#
#   emitted   `opa parse --format json --json-include locations` over the
#             non-test sources. The AST has no comments in it, so prose about a
#             rule is not a rule, and every string literal carries the row it
#             sits on.
#   exercised `opa test --coverage`. The `msg := ...` assignment is the last
#             expression in a deny body, so it is reached only when the rule
#             actually fired against some input. Coverage is reported as
#             expression spans, so the span enclosing an ID literal answers
#             "did a test trip this" — for inline test inputs as well as for
#             fixtures under test/fixtures/.
#
# The unit is the emission site, not the ID. K8S-007 denies `:latest` and an
# untagged image from two separate rule bodies; a test for one proves nothing
# about the other, and collapsing them under one ID would hide that.
#
# Both sides are discovered at run time. No rule list lives in this script, so
# a new package is under the gate the moment it is committed — which is the
# only version of this check that survives contact with a growing policy set.
#
# The one assumption: a rule ID literal appears inside the rule that emits it.
# A package that kept its IDs in a lookup table elsewhere would be measured on
# the table's coverage instead, and would need a different reading here.
set -euo pipefail

OPA="${OPA:-opa}"

# Paths in the coverage report and in the parse output are the paths handed to
# opa, so both sides have to be produced from the same working directory for
# the join to line up.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if ! "$OPA" test policy/ test/ data/ --coverage --format json >"$work/coverage.json"; then
	echo "rule-coverage: the test suite does not pass, so coverage says nothing yet — run 'make test'" >&2
	exit 1
fi

# One parse per policy file rather than per directory, so the file name in the
# emitted record is the same string the coverage report is keyed by.
: >"$work/sites.jsonl"
while IFS= read -r source; do
	"$OPA" parse "$source" --format json --json-include locations,-comments |
		jq -c --arg file "$source" '
			[ ..
			| objects
			| select(.type == "string" and (.value | type == "string"))
			| select(.value | test("^[A-Z][A-Z0-9]*-[0-9]+$"))
			| {id: .value, file: $file, row: .location.row}
			]
			| unique[]
		' >>"$work/sites.jsonl"
done < <(find policy -name '*.rego' ! -name '*_test.rego' | sort)

jq -s --slurpfile coverage "$work/coverage.json" '
	($coverage[0].files // {}) as $files
	| map(. as $site
		| .covered = (
			($files[$site.file].covered // [])
			| any(.start.row <= $site.row and .end.row >= $site.row)
		))
	| sort_by(.id, .file, .row)
' "$work/sites.jsonl" >"$work/sites.json"

total="$(jq 'length' "$work/sites.json")"
covered="$(jq '[.[] | select(.covered)] | length' "$work/sites.json")"

if [[ "$total" -eq 0 ]]; then
	echo "rule-coverage: found no rule IDs in policy/ — the extraction is broken, not the policies" >&2
	exit 1
fi

if [[ "$covered" -ne "$total" ]]; then
	echo "rule-coverage: $covered/$total rule emission sites are exercised by the test suite" >&2
	echo >&2
	jq -r '.[] | select(.covered | not) | "  \(.id)  \(.file):\(.row)  no test trips this rule"' \
		"$work/sites.json" >&2
	echo >&2
	echo "Add a fixture under test/fixtures/ and an assertion in the package's _test.rego." >&2
	exit 1
fi

echo "rule-coverage: $total/$total rule emission sites exercised — $(jq -r '[.[].id] | unique | join(", ")' "$work/sites.json")"
