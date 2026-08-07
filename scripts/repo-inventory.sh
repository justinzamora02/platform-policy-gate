#!/usr/bin/env bash
# Emit a repository inventory document for the policy/repo package:
#
#   {"files": ["Makefile", "README.md", ...], "node": {...}}
#
# Lists the working tree as git sees it, minus anything gitignored, so a local
# run and a CI checkout (where everything is tracked) agree.
set -euo pipefail

root="${1:-.}"

if [[ -f "$root/package.json" ]]; then
	git -C "$root" ls-files --cached --others --exclude-standard |
		jq -Rn --slurpfile package "$root/package.json" '
			[inputs] as $files |
			{
				files: $files,
				node: {
					packageManager: ($package[0].packageManager // null),
					engines: ($package[0].engines // {}),
					scripts: ($package[0].scripts // {}),
					lockfiles: [$files[] | select(
						. == "package-lock.json" or
						. == "npm-shrinkwrap.json" or
						. == "pnpm-lock.yaml" or
						. == "yarn.lock" or
						. == "bun.lock" or
						. == "bun.lockb"
					)],
					ciFiles: [$files[] | select(startswith(".github/workflows/"))]
				}
			}
		'
else
	git -C "$root" ls-files --cached --others --exclude-standard |
		jq -Rn '{files: [inputs]}'
fi
