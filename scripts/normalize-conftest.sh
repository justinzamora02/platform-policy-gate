#!/usr/bin/env bash
# Normalize `conftest test -o json` output into this project's finding shape:
# {id, severity, enforcement, file, resource, msg}.
#
# Usage: normalize-conftest.sh <conftest-json-file>...
#
# Conftest splits a finding across `.metadata` (the structured fields) and
# `.msg` on the `failures`/`warnings` entry; this pulls both onto one object.
set -euo pipefail

if [[ $# -eq 0 ]]; then
	echo "usage: normalize-conftest.sh <conftest-json-file>..." >&2
	exit 2
fi

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
