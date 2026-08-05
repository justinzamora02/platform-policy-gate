#!/usr/bin/env bash
# Normalize `hadolint --format json` output into this project's finding
# shape: {id, severity, enforcement, file, resource, msg}.
#
# Usage: normalize-hadolint.sh <hadolint-json-file>
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: normalize-hadolint.sh <hadolint-json-file>" >&2
	exit 2
fi

# Hadolint levels are error/warning/info/style. error and warning are the ones
# Hadolint treats as hygiene problems rather than style, so those deny.
jq -c '
	map({
		id: .code,
		severity: (
			if .level == "error" then "high"
			elif .level == "warning" then "medium"
			else "low"
			end
		),
		enforcement: (if .level == "error" or .level == "warning" then "deny" else "warn" end),
		file: .file,
		resource: "line \(.line)",
		msg: .message
	})
' "$1"
