package github_test

import data.fixtures
import data.github
import rego.v1

# Collect the rule IDs a fixture triggers, so assertions name rules rather
# than counting messages.
ids(fixture) := {msg.id | some msg in github.deny with input as fixture}

# --- GHA-001 --------------------------------------------------------------

test_gha_001_allows_sha_pinned_actions if {
	ids(fixtures.github.compliant) == set()
}

test_gha_001_denies_tag_pinned_actions if {
	ids(fixtures.github["floating-tag"]) == {"GHA-001"}
}

test_gha_001_ignores_local_actions if {
	# `./`-prefixed and `run:` steps both live in the compliant fixture; if
	# either were treated as a third-party action it would fail to pin.
	ids(fixtures.github.compliant) == set()
}

test_gha_001_denies_unpinned_reusable_workflow_call if {
	workflow := {
		"on": {"pull_request": null},
		"permissions": {},
		"jobs": {"call": {"uses": "actions/checkout@v5"}},
	}
	ids(workflow) == {"GHA-001"}
}

test_gha_001_names_the_step_it_found if {
	some msg in github.deny with input as fixtures.github["floating-tag"]
	msg.id == "GHA-001"
	msg.resource == "jobs.build.steps[0]"
}

# --- GHA-002 --------------------------------------------------------------

test_gha_002_denies_unapproved_action if {
	ids(fixtures.github["unapproved-action"]) == {"GHA-002"}
}

test_gha_002_matches_subpath_actions_on_owner_repo if {
	workflow := workflow_with_step({"uses": "actions/github-script/dist@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"})
	ids(workflow) == set()
}

test_gha_002_names_the_allowlist_key_rather_than_the_raw_uses if {
	# A subpath reference, so the allowlist key and the raw `uses` differ: the
	# finding has to name the string that goes in data/gha.yaml.
	workflow := workflow_with_step({"uses": "some-vendor/deploy-action/setup@1b21df8e4b40e0b8b6c8c0c9f4d0e6a5c3b2a190"})
	some msg in github.deny with input as workflow
	msg.id == "GHA-002"
	msg.msg == `action "some-vendor/deploy-action" is not in the approved_actions list in data/gha.yaml`
}

test_gha_002_denies_references_it_cannot_parse if {
	# No ref at all, so there is nothing to check against the allowlist.
	# Fails closed rather than falling through as approved.
	ids(workflow_with_step({"uses": "actions/checkout"})) == {"GHA-002"}
}

test_gha_002_fails_closed_without_an_allowlist if {
	msgs := github.deny with input as fixtures.github.compliant
		with data.gha.approved_actions as []

	{msg.id | some msg in msgs} == {"GHA-002"}
}

# --- GHA-003 --------------------------------------------------------------

test_gha_003_denies_unapproved_label_beside_an_approved_one if {
	ids(fixtures.github["unapproved-runner"]) == {"GHA-003"}
}

test_gha_003_reads_labels_from_a_runner_group if {
	workflow := {
		"on": {"pull_request": null},
		"permissions": {},
		"jobs": {"build": {
			"runs-on": {"group": "default", "labels": ["self-hosted"]},
			"steps": [],
		}},
	}
	ids(workflow) == {"GHA-003"}
}

test_gha_003_reports_the_offending_label if {
	some msg in github.deny with input as fixtures.github["unapproved-runner"]
	msg.runner == "self-hosted"
	msg.resource == "jobs.build"
}

# --- scope and parsing ----------------------------------------------------

# The `on:` key is a YAML 1.1 boolean, so it reaches the policy in one of three
# shapes depending on the parser. All three are asserted directly: this is the
# one bug in the package that would present as a passing check rather than a
# failing one.
test_workflow_detected_with_string_on_key if {
	github.is_workflow with input as {"on": {"push": null}, "jobs": {}}
}

test_workflow_detected_with_stringified_boolean_key if {
	github.is_workflow with input as {"true": {"push": null}, "jobs": {}}
}

test_workflow_detected_with_boolean_on_key if {
	github.is_workflow with input as {true: {"push": null}, "jobs": {}}
}

test_fixture_on_key_survives_the_parser if {
	# Belt and braces: whichever form this loader produced from an unquoted
	# `on:`, the real file is in scope.
	github.is_workflow with input as fixtures.github.compliant
}

test_non_workflow_documents_are_out_of_scope if {
	not github.is_workflow with input as fixtures.github["not-a-workflow"]
	ids(fixtures.github["not-a-workflow"]) == set()
}

test_messages_are_structured if {
	some msg in github.deny with input as fixtures.github["floating-tag"]
	msg.severity == "high"
	msg.enforcement == "deny"
	is_string(msg.resource)
	is_string(msg.msg)
}

# --- GHA-004 --------------------------------------------------------------

test_gha_004_denies_missing_permissions if {
	workflow := object.remove(workflow_with_step({"run": "echo ok"}), ["permissions"])
	some msg in github.deny with input as workflow
	msg.id == "GHA-004"
}

test_gha_004_denies_write_all if {
	workflow := object.union(workflow_with_step({"run": "echo ok"}), {"permissions": "write-all"})
	some msg in github.deny with input as workflow
	msg.id == "GHA-004"
}

test_gha_004_allows_explicit_permissions_map if {
	workflow := object.union(workflow_with_step({"run": "echo ok"}), {"permissions": {"contents": "read"}})
	not "GHA-004" in {msg.id | some msg in github.deny with input as workflow}
}

workflow_with_step(step) := {
	"on": {"pull_request": null},
	"permissions": {},
	"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [step]}},
}
