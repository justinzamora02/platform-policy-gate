#!/usr/bin/env bash
# Normalize Conftest JSON results into one finding shape and render a single
# job summary, instead of a reviewer reading raw `conftest test` output once
# per matrix leg.
#
# Each matrix leg writes its own `conftest test -o json` result to a file;
# this script is the one place that reads all of them and decides the run's
# outcome, so a caller sees one summary and one exit code, not N.
#
# Usage: aggregate-findings.sh <conftest-json-file>...
#
# A file that holds `[]` (no documents evaluated, e.g. "no charts found") is
# valid input and contributes no findings.
set -euo pipefail

if [[ $# -eq 0 ]]; then
	echo "usage: aggregate-findings.sh <conftest-json-file>..." >&2
	exit 2
fi

# jq flattens every file's [{filename, failures[], warnings[]}, ...] into one
# array of {id, severity, enforcement, file, resource, msg}. Conftest puts the
# structured fields this project's Rego emits under `.metadata`, and the text
# a rule composed with `sprintf` under `.msg` — pulling both back together here
# is what makes the two `deny`/`warn` arrays into one finding shape.
findings_json="$(
	jq -cs '
		[
			.[][] as $file |
			($file.failures // [])[] as $f | {enforcement: "deny", finding: $f, filename: $file.filename},
			($file.warnings // [])[] as $w | {enforcement: "warn", finding: $w, filename: $file.filename}
		] | map({
			id: (.finding.metadata.id // "UNKNOWN"),
			severity: (.finding.metadata.severity // "unknown"),
			enforcement,
			file: .filename,
			resource: (.finding.metadata.resource // ""),
			msg: .finding.msg
		})
	' "$@"
)"

severity_rank='{"high": 0, "medium": 1, "low": 2}'

render_group() {
	local enforcement="$1"
	local heading="$2"
	local group
	group="$(jq -c --arg e "$enforcement" --argjson rank "$severity_rank" '
		map(select(.enforcement == $e))
		| sort_by([($rank[.severity] // 99), .id, .file])
	' <<<"$findings_json")"

	local count
	count="$(jq 'length' <<<"$group")"
	if [[ "$count" -eq 0 ]]; then
		return
	fi

	printf '### %s (%s)\n\n' "$heading" "$count"
	printf '| Rule | Severity | Resource | File | Message |\n'
	printf '|---|---|---|---|---|\n'
	jq -r '.[] | "| \(.id) | \(.severity) | \(.resource) | \(.file) | \(.msg) |"' <<<"$group"
	printf '\n'
}

deny_count="$(jq '[.[] | select(.enforcement == "deny")] | length' <<<"$findings_json")"
warn_count="$(jq '[.[] | select(.enforcement == "warn")] | length' <<<"$findings_json")"

summary="$(
	printf '## Policy findings\n\n'
	if [[ "$deny_count" -eq 0 && "$warn_count" -eq 0 ]]; then
		printf 'No findings.\n'
	else
		# Deny before warn: a reviewer scrolling a long summary hits the
		# blocking findings first, not after paging past everything advisory.
		render_group "deny" "Deny"
		render_group "warn" "Warn"
	fi
)"

printf '%s\n' "$summary"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
	printf '%s\n' "$summary" >>"$GITHUB_STEP_SUMMARY"
fi

# The gate: any `deny` finding fails the run, regardless of which matrix leg
# or tool produced it. `warn` findings are surfaced but never fail on their
# own unless the caller opted into FAIL_ON_WARN — the same grace-period switch
# `policy-check.yml` exposes as `fail-on-warn`, now enforced here instead of
# per-leg, since this script is the one place that sees every finding.
if [[ "$deny_count" -gt 0 ]]; then
	exit 1
fi

if [[ "${FAIL_ON_WARN:-false}" == "true" && "$warn_count" -gt 0 ]]; then
	exit 1
fi
