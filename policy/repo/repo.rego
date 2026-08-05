# Repo hygiene policies. Input is a `{"files": [...]}` inventory document,
# generated from the consumer's working tree by scripts/repo-inventory.sh, not a
# manifest.
package repo

import rego.v1

# REPO-001: a LICENSE file must be present at the repository root. The `files`
# guard scopes the rule to inventory documents; without it the absent key makes
# `not has_license` true for every manifest Conftest is pointed at.
deny contains msg if {
	is_array(input.files)
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

# REPO-002: CODEOWNERS must live in one of GitHub's three recognized paths.
# Repeating the inventory-shape guard is deliberate, for the reason above.
deny contains msg if {
	is_array(input.files)
	not has_codeowners

	msg := {
		"id": "REPO-002",
		"severity": "medium",
		"enforcement": "deny",
		"resource": "repository",
		"msg": "no CODEOWNERS file at the repository root, .github/, or docs/",
	}
}

codeowners_paths := {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}

has_codeowners if {
	some path in input.files
	path in codeowners_paths
}
