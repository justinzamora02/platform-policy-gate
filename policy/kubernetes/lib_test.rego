package kubernetes.lib_test

import data.fixtures
import data.kubernetes.lib
import rego.v1

# The container names the traversal reaches for a fixture. Asserting on names
# rather than a count makes a failure say which container went missing.
names(fixture) := {container.name | some container in found} if {
	found := lib.containers with input as fixture
}

# Every workload kind resolves to the same two containers. The point of the
# table is that adding a kind to lib.pod_spec without a fixture here is visible
# as a gap, not that any one of these paths is interesting on its own.
test_traversal_reaches_containers_for_every_workload_kind if {
	every kind in [
		"pod",
		"deployment",
		"statefulset",
		"daemonset",
		"replicaset",
		"job",
		"cronjob",
	] {
		names(fixtures.kubernetes[sprintf("%s-compliant", [kind])]) == {"app", "init"}
	}
}

test_pod_spec_is_undefined_for_non_workload_kinds if {
	not lib.pod_spec with input as fixtures.kubernetes.service
}

test_traversal_yields_nothing_for_non_workload_kinds if {
	names(fixtures.kubernetes.service) == set()
}

test_traversal_includes_init_containers if {
	names(fixtures.kubernetes["pod-privileged-init"]) == {"app", "init"}
}

test_traversal_handles_a_pod_without_init_containers if {
	names(fixtures.kubernetes["pod-inherits-non-root"]) == {"app"}
}

# The three states of the inherited securityContext lookup: set on the
# container, absent and taken from the pod, and absent from both.
test_inherited_security_context_prefers_the_container if {
	container := {"securityContext": {"runAsNonRoot": false}}
	lib.inherited_security_context(container, "runAsNonRoot") == false with input as fixtures.kubernetes["pod-inherits-non-root"]
}

test_inherited_security_context_falls_back_to_the_pod if {
	lib.inherited_security_context({"name": "app"}, "runAsNonRoot") == true with input as fixtures.kubernetes["pod-inherits-non-root"]
}

test_inherited_security_context_is_null_when_neither_level_sets_it if {
	lib.inherited_security_context({"name": "app"}, "runAsNonRoot") == null with input as fixtures.kubernetes["pod-run-as-root"]
}

# Image reference parsing.
#
# Tabled rather than split into one test per case because the cases only mean
# something against each other: every entry below is a reference that a naive
# `split(image, "/")[0]` or `split(image, ":")[1]` gets wrong in one direction
# or the other.
test_image_registry_resolves_every_reference_form if {
	every image, registry in {
		"registry.example.com/app:1.0.0": "registry.example.com",
		"ghcr.io/org/team/app:1.0.0": "ghcr.io",
		"localhost:5000/app:1.0.0": "localhost:5000",
		"registry.example.com:5000/app:1.0.0": "registry.example.com:5000",
		# No host-looking first component: Docker Hub, however many path
		# segments follow.
		"nginx:1.27": "docker.io",
		"nginx": "docker.io",
		"myorg/app:1.0.0": "docker.io",
		"library/nginx:1.27": "docker.io",
	} {
		lib.image_registry(image) == registry
	}
}

test_image_tag_reads_only_the_last_path_component if {
	every image, tag in {
		"registry.example.com/app:1.0.0": "1.0.0",
		"registry.example.com/app:latest": "latest",
		"nginx:1.27": "1.27",
		"localhost:5000/app:1.0.0": "1.0.0",
	} {
		lib.image_tag(image) == tag
	}
}

test_image_tag_is_undefined_without_one if {
	not lib.image_tag("registry.example.com/app")
	not lib.image_tag("nginx")

	# The port is the only colon here, and it is not a tag.
	not lib.image_tag("localhost:5000/app")

	# The digest hex is the only colon here, and it is not a tag either.
	not lib.image_tag("registry.example.com/app@sha256:abc123")
}

test_image_digest_reads_the_pin if {
	lib.image_digest("registry.example.com/app@sha256:abc123") == "sha256:abc123"
	not lib.image_digest("registry.example.com/app:1.0.0")
}

test_resource_names_the_kind_and_the_object if {
	lib.resource == "Deployment/compliant-deployment" with input as fixtures.kubernetes["deployment-compliant"]
}

test_container_finding_carries_the_container_name if {
	finding := lib.container_finding("K8S-000", "low", {"name": "app"}, "text") with input as fixtures.kubernetes["pod-compliant"]

	finding == {
		"id": "K8S-000",
		"severity": "low",
		"enforcement": "deny",
		"resource": "Pod/compliant-pod",
		"container": "app",
		"msg": "text",
	}
}
