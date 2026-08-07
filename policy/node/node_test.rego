package node_test

import data.fixtures
import data.node
import rego.v1

ids(fixture) := {msg.id | some msg in node.deny with input as fixture}

test_node_rules_allow_a_supported_pnpm_project if {
	ids(fixtures.node.compliant) == set()
}

test_node_001_denies_a_missing_package_manager if {
	ids(fixtures.node["missing-package-manager"]) == {"NODE-001"}
}

test_node_001_denies_a_non_exact_pnpm_version if {
	ids(fixtures.node["package-manager-range"]) == {"NODE-001"}
}

test_node_002_denies_an_unapproved_node_constraint if {
	ids(fixtures.node["unapproved-node-version"]) == {"NODE-002"}
}

test_node_002_fails_closed_without_approved_constraints if {
	ids(fixtures.node.compliant) == {"NODE-002"} with data.node_policy.approved_node_constraints as []
}

test_node_003_denies_a_missing_pnpm_lockfile if {
	ids(fixtures.node["missing-pnpm-lockfile"]) == {"NODE-003"}
}

test_node_004_denies_each_disallowed_root_lockfile if {
	findings := {msg.resource | some msg in node.deny with input as fixtures.node["disallowed-lockfiles"]; msg.id == "NODE-004"}
	findings == {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb"}
}

test_non_node_documents_are_out_of_scope if {
	ids(fixtures.kubernetes.service) == set()
	ids({"kind": "node-project", "path": "packages/app/package.json", "manifest": {}, "tracked_files": []}) == set()
	ids({"kind": "node-project", "path": "package.json", "manifest": {}}) == set()
}

test_findings_are_structured if {
	some msg in node.deny with input as fixtures.node["missing-pnpm-lockfile"]
	msg.id == "NODE-003"
	msg.severity == "high"
	msg.enforcement == "deny"
	msg.resource == "pnpm-lock.yaml"
	is_string(msg.msg)
}
