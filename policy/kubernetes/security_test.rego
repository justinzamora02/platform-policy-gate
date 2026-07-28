package kubernetes_test

import data.fixtures
import data.kubernetes
import rego.v1

# Collect the rule IDs a fixture triggers, so assertions name rules rather than
# counting messages.
ids(fixture) := {msg.id | some msg in found} if {
	found := kubernetes.deny with input as fixture
}

# The containers a given rule reports, for the fixtures where which container
# was caught is the point.
containers_flagged(fixture, id) := {msg.container | some msg in found; msg.id == id} if {
	found := kubernetes.deny with input as fixture
}

messages(fixture, id) := {msg.msg | some msg in found; msg.id == id} if {
	found := kubernetes.deny with input as fixture
}

# Every compliant fixture must be silent on all four rules. Running the table
# over each kind catches a rule that reads the PodSpec directly off `input`
# instead of going through the traversal.
test_compliant_workloads_are_clean if {
	every kind in [
		"pod",
		"deployment",
		"statefulset",
		"daemonset",
		"replicaset",
		"job",
		"cronjob",
	] {
		ids(fixtures.kubernetes[sprintf("%s-compliant", [kind])]) == set()
	}
}

test_non_workload_kinds_are_clean if {
	ids(fixtures.kubernetes.service) == set()
}

# K8S-001

test_k8s_001_denies_a_privileged_container if {
	ids(fixtures.kubernetes["pod-privileged"]) == {"K8S-001"}
	containers_flagged(fixtures.kubernetes["pod-privileged"], "K8S-001") == {"app"}
}

test_k8s_001_denies_a_privileged_init_container if {
	containers_flagged(fixtures.kubernetes["pod-privileged-init"], "K8S-001") == {"init"}
}

# `privileged: false` is the common explicit case and must not be read as
# truthy, which a bare `container.securityContext.privileged` would do.
test_k8s_001_allows_privileged_false if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"containers": [{
				"name": "app",
				"securityContext": {"privileged": false},
			}],
		},
	}

	ids(pod) == set()
}

# K8S-002

test_k8s_002_denies_when_neither_level_sets_non_root if {
	ids(fixtures.kubernetes["pod-run-as-root"]) == {"K8S-002"}
	containers_flagged(fixtures.kubernetes["pod-run-as-root"], "K8S-002") == {"app", "init"}
}

test_k8s_002_allows_a_container_inheriting_from_the_pod if {
	ids(fixtures.kubernetes["pod-inherits-non-root"]) == set()
}

test_k8s_002_denies_a_container_that_overrides_the_pod_to_root if {
	ids(fixtures.kubernetes["pod-container-overrides-non-root"]) == {"K8S-002"}
	containers_flagged(fixtures.kubernetes["pod-container-overrides-non-root"], "K8S-002") == {"app"}
}

# K8S-003

test_k8s_003_denies_each_host_namespace_separately if {
	ids(fixtures.kubernetes["pod-host-namespaces"]) == {"K8S-003"}

	messages(fixtures.kubernetes["pod-host-namespaces"], "K8S-003") == {
		"pod sets hostNetwork: true",
		"pod sets hostPID: true",
		"pod sets hostIPC: true",
	}
}

test_k8s_003_allows_host_namespaces_set_to_false if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {
			"hostNetwork": false,
			"hostPID": false,
			"hostIPC": false,
			"securityContext": {"runAsNonRoot": true},
			"containers": [{"name": "app"}],
		},
	}

	ids(pod) == set()
}

# K8S-004

test_k8s_004_denies_a_host_path_volume if {
	ids(fixtures.kubernetes["pod-hostpath"]) == {"K8S-004"}

	messages(fixtures.kubernetes["pod-hostpath"], "K8S-004") == {`volume "docker-socket" mounts host path "/var/run/docker.sock"`}
}

# A hostPath without its API-required `path` still has to be reported; the
# message degrades instead of the finding disappearing.
test_k8s_004_denies_a_host_path_missing_its_path if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"volumes": [{"name": "vol", "hostPath": {}}],
			"containers": [{"name": "app"}],
		},
	}

	messages(pod, "K8S-004") == {`volume "vol" mounts host path "(unspecified)"`}
}

# Shape

test_findings_are_structured if {
	some msg in kubernetes.deny with input as fixtures.kubernetes["pod-privileged"]
	msg.id == "K8S-001"
	msg.severity == "high"
	msg.enforcement == "deny"
	msg.resource == "Pod/privileged-pod"
	msg.container == "app"
	is_string(msg.msg)
}
