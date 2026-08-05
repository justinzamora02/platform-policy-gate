#!/usr/bin/env bash
# Normalize `zizmor --format json` output into this project's finding shape:
# {id, severity, enforcement, file, resource, msg}.
#
# Usage: normalize-zizmor.sh <zizmor-json-file>
#
# GHA-001 is implemented in Rego on purpose, to show the parsing; Zizmor owns
# the deeper analysis (injection, permissions, artifact poisoning) that the
# Rego doesn't attempt. This script is what lets its findings land in the same
# summary as the Rego's, not a second, differently-shaped report.
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: normalize-zizmor.sh <zizmor-json-file>" >&2
	exit 2
fi

# Zizmor's own severities are Unknown/Informational/Low/Medium/High.
# Informational and Low findings are surfaced but don't block a run on their
# own, matching this project's enforcement convention — only Medium/High deny.
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
