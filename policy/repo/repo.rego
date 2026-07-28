# Repo hygiene policies.
#
# Input is a repository inventory document, not a manifest:
#
#   files:
#     - LICENSE
#     - README.md
#     - CODEOWNERS
#
# `make inventory` (and the reusable workflow) generates it from the
# consumer's working tree. Evaluating a list of paths keeps "is this file
# present?" rules out of the manifest policies, which only ever see one
# rendered document at a time.
#
# Rules emit an object rather than a bare string. Conftest requires the human
# text under `msg` and surfaces every other key under `metadata`, which is what
# the aggregation step consumes.
package repo

import rego.v1

# REPO-001: a LICENSE file must be present at the repository root.
deny contains msg if {
	not has_license

	msg := {
		"id": "REPO-001",
		"severity": "medium",
		"enforcement": "deny",
		"resource": "repository",
		"msg": "no LICENSE file at the repository root",
	}
}

license_names := {"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"}

has_license if {
	some path in input.files
	path in license_names
}
