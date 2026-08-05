#!/usr/bin/env bash
# Normalize `zizmor --format json` output into this project's finding shape:
# {id, severity, enforcement, file, resource, msg}.
#
# Usage: normalize-zizmor.sh <zizmor-json-file>
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: normalize-zizmor.sh <zizmor-json-file>" >&2
	exit 2
fi

# Zizmor severities are Unknown/Informational/Low/Medium/High. Only Medium and
# High deny; the rest are surfaced as warnings.
jq -c '
	map({
		id: .ident,
		severity: (
			if .determinations.severity == "High" then "high"
			elif .determinations.severity == "Medium" then "medium"
			else "low"
			end
		),
		enforcement: (if .determinations.severity == "High" or .determinations.severity == "Medium" then "deny" else "warn" end),
		file: (.locations[0].symbolic.key.Local.verbatim_path // "unknown"),
		resource: (.locations[0].symbolic.annotation // ""),
		msg: .desc
	})
' "$1"
