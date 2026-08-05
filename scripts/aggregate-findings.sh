#!/usr/bin/env bash
# Merge already-normalized finding files into one job summary and gate.
#
# Usage: aggregate-findings.sh <normalized-findings-json-file>...
#
# Each source has its own scripts/normalize-*.sh that maps its native output to
# {id, severity, enforcement, file, resource, msg}; this script only merges the
# results, so a new source never touches the merge/render/gate logic. A file
# holding `[]` is valid input and contributes no findings.
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
		# Deny before warn, so a long summary leads with what blocks the run.
		render_group "deny" "Deny"
		render_group "warn" "Warn"
	fi
)"

printf '%s\n' "$summary"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
	printf '%s\n' "$summary" >>"$GITHUB_STEP_SUMMARY"
fi

# The gate: any `deny` fails the run, whichever leg or tool produced it. `warn`
# only fails under FAIL_ON_WARN (`fail-on-warn` in policy-check.yml). Enforced
# here rather than per-leg, since this is the one place that sees every finding.
if [[ "$deny_count" -gt 0 ]]; then
	exit 1
fi

if [[ "${FAIL_ON_WARN:-false}" == "true" && "$warn_count" -gt 0 ]]; then
	exit 1
fi
