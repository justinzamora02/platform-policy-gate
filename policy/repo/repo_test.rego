package repo_test

import data.fixtures
import data.repo
import rego.v1

# Collect the rule IDs a fixture triggers, so assertions name rules rather
# than counting messages.
ids(fixture) := out if {
	msgs := repo.deny with input as fixture
	out := {msg.id | some msg in msgs}
}

test_repo_001_allows_license_at_root if {
	ids(fixtures.repo["license-present"]) == set()
}

test_repo_001_denies_missing_license if {
	ids(fixtures.repo["license-missing"]) == {"REPO-001"}
}

test_repo_001_accepts_alternate_license_names if {
	every name in ["LICENSE.md", "LICENSE.txt", "COPYING"] {
		ids({"files": ["README.md", name]}) == set()
	}
}

# Conftest hands every package every file it was pointed at, so the rule has to
# stay silent on documents that are not inventories. The failure mode is a
# manifest reported as missing a LICENSE, which is why it is asserted directly.
test_repo_001_ignores_non_inventory_documents if {
	ids(fixtures.kubernetes["pod-compliant"]) == set()
	ids(fixtures.github.compliant) == set()
}

test_repo_001_message_is_structured if {
	some msg in repo.deny with input as fixtures.repo["license-missing"]
	msg.severity == "medium"
	msg.enforcement == "deny"
	msg.resource == "repository"
	is_string(msg.msg)
}
