#!/usr/bin/env bash
# Suppress findings covered by a valid, unexpired entry in a consumer's
# `.platform-policy-exceptions.yaml`.
#
# Usage: apply-exceptions.sh <exceptions-yaml-file> <normalized-findings-json-file>
#
# Only policy/exceptions/exceptions.rego decides which entries are usable
# (`data.exceptions.active`) — this script never re-derives that judgment, so
# an invalid or expired entry that fails closed in the Rego cannot still
# suppress a finding here.
set -euo pipefail

OPA="${OPA:-opa}"

if [[ $# -ne 2 ]]; then
	echo "usage: apply-exceptions.sh <exceptions-yaml-file> <normalized-findings-json-file>" >&2
	exit 2
fi

exceptions_file="$1"
findings_file="$2"

# No exceptions file is the common case (most consumers have none) and is not
# an error: every finding passes through unsuppressed.
if [[ ! -f "$exceptions_file" ]]; then
	cat "$findings_file"
	exit 0
fi

policy_root="$(dirname "${BASH_SOURCE[0]}")/../policy"

active="$(
	"$OPA" eval -d "$policy_root" -i "$exceptions_file" -f json 'data.exceptions.active' \
		| jq -c '.result[0].expressions[0].value // []'
)"

# A match on `id` alone suppresses every finding for that rule; a `resource`
# on the exception narrows it to findings naming that exact resource.
jq -c --argjson active "$active" '
	map(select(
		. as $finding |
		[$active[] |
			select(.id == $finding.id) |
			select(.resource == null or .resource == $finding.resource)
		] == []
	))
' "$findings_file"
