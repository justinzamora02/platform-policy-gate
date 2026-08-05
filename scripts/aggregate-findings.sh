#!/usr/bin/env bash
# Merge already-normalized finding files into one job summary and gate.
#
# Each source — Conftest, Zizmor, Hadolint — has its own
# scripts/normalize-*.sh that maps its native output to this project's finding
# shape: {id, severity, enforcement, file, resource, msg}. This script only
# merges those already-normalized arrays; keeping the per-source mapping out
# of it is what let Zizmor and Hadolint join the summary without touching this
# file's merge/render/gate logic.
#
# Usage: aggregate-findings.sh <normalized-findings-json-file>...
#
# A file that holds `[]` is valid input and contributes no findings.
set -euo pipefail

if [[ $# -eq 0 ]]; then
	echo "usage: aggregate-findings.sh <normalized-findings-json-file>..." >&2
	exit 2
fi

findings_json="$(jq -cs 'add' "$@")"

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
