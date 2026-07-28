#!/usr/bin/env bash
# Emit a repository inventory document for the policy/repo package:
#
#   {"files": ["Makefile", "README.md", ...]}
#
# Lists the working tree as git sees it, minus anything gitignored, so a local
# run and a CI checkout (where everything is tracked) agree.
set -euo pipefail

root="${1:-.}"

git -C "$root" ls-files --cached --others --exclude-standard |
	jq -Rn '{files: [inputs]}'
