package dockerfile_test

import data.dockerfile
import data.fixtures
import rego.v1

# Collect IDs instead of counts so a fixture cannot pass by trading one wrong
# finding for the expected one.
ids(fixture) := {msg.id | some msg in dockerfile.deny with input as fixture}

# --- DOCKER-001 -----------------------------------------------------------

test_docker_001_allows_approved_registries if {
	ids(fixtures.dockerfile.compliant) == set()
}

test_docker_001_denies_unapproved_registries if {
	ids(fixtures.dockerfile["unapproved-registry"]) == {"DOCKER-001"}
}

test_docker_001_resolves_bare_images_to_docker_hub if {
	dockerfile.image_registry("golang:1.22") == "docker.io"
}

test_docker_001_fails_closed_without_an_allowlist if {
	ids(fixtures.dockerfile.compliant) == {"DOCKER-001"} with data.docker.approved_registries as []
}

# --- DOCKER-002 -----------------------------------------------------------

test_docker_002_allows_versioned_tags if {
	ids(fixtures.dockerfile.compliant) == set()
}

test_docker_002_denies_latest if {
	ids(fixtures.dockerfile["latest-tag"]) == {"DOCKER-002"}
}

test_docker_002_denies_untagged_images if {
	ids(fixtures.dockerfile.untagged) == {"DOCKER-002"}
}

test_docker_002_allows_digest_pins if {
	dockerfile_input := [from("registry.example.com/base@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", 0), user("1000", 0)]
	ids(dockerfile_input) == set()
}

# --- DOCKER-003 -----------------------------------------------------------

test_docker_003_denies_a_missing_final_user if {
	ids([from("registry.example.com/base:1.0", 0)]) == {"DOCKER-003"}
}

test_docker_003_denies_root_in_the_final_stage if {
	dockerfile_input := [from("registry.example.com/base:1.0", 0), user("root", 0)]
	ids(dockerfile_input) == {"DOCKER-003"}
}

test_docker_003_allows_a_non_root_final_user if {
	dockerfile_input := [from("registry.example.com/base:1.0", 0), user("1000", 0)]
	ids(dockerfile_input) == set()
}

test_docker_003_uses_the_last_user_in_the_final_stage if {
	dockerfile_input := [from("registry.example.com/base:1.0", 0), user("root", 0), user("1000", 0)]
	ids(dockerfile_input) == set()
}

# --- stages and scope -----------------------------------------------------

test_stage_aliases_are_not_external_images if {
	{stage.image | some stage in dockerfile.external_stages with input as fixtures.dockerfile.compliant} == {
		"ghcr.io/acme/runtime:2.0.0",
		"registry.example.com/toolchain:1.22.0",
	}
	ids(fixtures.dockerfile.compliant) == set()
}

# Conftest evaluates this package for every input file. These fixtures contain
# fields that would fail the image rules if they were treated as Dockerfile
# instructions, so zero findings proves the document-shape guard owns scope.
test_foreign_documents_are_out_of_scope if {
	ids(fixtures.kubernetes["pod-compliant"]) == set()
	ids(fixtures.helm.compliant) == set()
}

test_findings_are_structured if {
	some msg in dockerfile.deny with input as fixtures.dockerfile["latest-tag"]
	msg.id == "DOCKER-002"
	msg.severity == "medium"
	msg.enforcement == "deny"
	is_string(msg.resource)
	is_string(msg.msg)
}

from(image, stage) := {
	"Cmd": "from",
	"Flags": [],
	"JSON": false,
	"Stage": stage,
	"SubCmd": "",
	"Value": [image],
}

user(value, stage) := {
	"Cmd": "user",
	"Flags": [],
	"JSON": false,
	"Stage": stage,
	"SubCmd": "",
	"Value": [value],
}
