#!/usr/bin/env bash
# Normalize `hadolint --format json` output into this project's finding
# shape: {id, severity, enforcement, file, resource, msg}.
#
# Usage: normalize-hadolint.sh <hadolint-json-file>
#
# Hadolint owns every Dockerfile instruction except FROM, which
# policy/dockerfile/dockerfile.rego covers directly (DOCKER-001/002) — see the
# comment there. This script is what lets Hadolint's findings land in the same
# summary as the Rego's, not a second, differently-shaped report.
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: normalize-hadolint.sh <hadolint-json-file>" >&2
	exit 2
fi

# Hadolint's own levels are error/warning/info/style. error/warning deny —
# they are the levels Hadolint itself treats as build hygiene problems, not
# style opinions — info/style are surfaced but don't block a run on their own.
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
