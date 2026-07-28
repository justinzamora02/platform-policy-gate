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
