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

# Every compliant fixture must be silent on every rule in the package. Running the table
# over each kind catches a rule that reads the PodSpec directly off `input`
# instead of going through the traversal.
test_compliant_workloads_are_clean if {
	every kind in [
		"pod",
		"deployment",
		"statefulset",
		"daemonset",
		"replicaset",
		"replicationcontroller",
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

test_k8s_001_denies_a_privileged_pod_with_generate_name if {
	ids(fixtures.kubernetes["pod-privileged-generate-name"]) == {"K8S-001"}
	containers_flagged(fixtures.kubernetes["pod-privileged-generate-name"], "K8S-001") == {"app"}
}

test_k8s_001_denies_a_privileged_replication_controller if {
	fixture := fixtures.kubernetes["replicationcontroller-privileged"]
	containers_flagged(fixture, "K8S-001") == {"app"}
	messages(fixture, "K8S-001") == {`container "app" runs privileged`}
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

	not "K8S-001" in ids(pod)
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

	not "K8S-003" in ids(pod)
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

# K8S-008

test_k8s_008_denies_both_an_explicit_false_and_an_absent_field if {
	ids(fixtures.kubernetes["pod-writable-root-filesystem"]) == {"K8S-008"}
	containers_flagged(fixtures.kubernetes["pod-writable-root-filesystem"], "K8S-008") == {"app", "init"}
}

# The inheritance judgement call, pinned: `readOnlyRootFilesystem` is not a
# PodSecurityContext field, so a pod-level `true` is inert and must not clear
# the container. Reusing lib.inherited_security_context here would flip this
# test green while the cluster still mounts a writable root.
test_k8s_008_does_not_inherit_from_the_pod if {
	ids(fixtures.kubernetes["pod-pod-level-readonly-root"]) == {"K8S-008"}
	containers_flagged(fixtures.kubernetes["pod-pod-level-readonly-root"], "K8S-008") == {"app"}
}

test_k8s_008_allows_a_read_only_root_filesystem if {
	not "K8S-008" in ids(fixtures.kubernetes["deployment-compliant"])
}

# K8S-009

test_k8s_009_denies_a_partial_drop_and_an_absent_one if {
	ids(fixtures.kubernetes["pod-missing-capability-drop"]) == {"K8S-009"}
	containers_flagged(fixtures.kubernetes["pod-missing-capability-drop"], "K8S-009") == {"app", "init"}
}

test_k8s_009_allows_dropping_all if {
	not "K8S-009" in ids(fixtures.kubernetes["deployment-compliant"])
}

# Kubernetes matches capability names literally, so `all` is a capability that
# does not exist and drops nothing. A case-insensitive comparison would pass
# this pod.
test_k8s_009_denies_a_lowercase_all if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {"containers": [{
			"name": "app",
			"securityContext": {"capabilities": {"drop": ["all"]}},
		}]},
	}

	containers_flagged(pod, "K8S-009") == {"app"}
}

# Adding a capability back on top of `drop: [ALL]` is K8S-013's business, not
# this one's.
test_k8s_009_allows_a_capability_added_back_on_top_of_all if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {"containers": [{
			"name": "app",
			"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}},
		}]},
	}

	not "K8S-009" in ids(pod)
}

# K8S-013

# One finding per container naming every disallowed addition, not one per
# capability. The init container adds only NET_BIND_SERVICE and stays clean.
test_k8s_013_denies_capabilities_that_are_not_allowlisted if {
	ids(fixtures.kubernetes["pod-adds-capability"]) == {"K8S-013"}
	containers_flagged(fixtures.kubernetes["pod-adds-capability"], "K8S-013") == {"app"}

	messages(fixtures.kubernetes["pod-adds-capability"], "K8S-013") == {`container "app" adds capability NET_RAW, SYS_ADMIN`}
}

# The hole this rule exists to close: `drop: [ALL]` plus `add: [SYS_ADMIN]`
# passes K8S-009 and every other rule in the package.
test_k8s_013_denies_what_k8s_009_alone_allows if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {"containers": [{
			"name": "app",
			"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN"]}},
		}]},
	}

	not "K8S-009" in ids(pod)
	containers_flagged(pod, "K8S-013") == {"app"}
}

# Kubernetes matches capability names exactly, so `sys_admin` is not the
# allowlisted spelling of anything. Case-folding before the lookup would turn
# the allowlist into a fuzzy match.
test_k8s_013_denies_a_lowercase_capability_name if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {"containers": [{
			"name": "app",
			"securityContext": {"capabilities": {"add": ["net_bind_service"]}},
		}]},
	}

	messages(pod, "K8S-013") == {`container "app" adds capability net_bind_service`}
}

# The verdict follows the data file, with no edit to any rule.
test_k8s_013_verdict_follows_the_data_file if {
	pod := fixtures.kubernetes["pod-adds-capability"]

	containers_flagged(pod, "K8S-013") == {"app"} with data.k8s.allowed_capabilities as ["NET_BIND_SERVICE", "NET_RAW"]
	messages(pod, "K8S-013") == {`container "app" adds capability SYS_ADMIN`} with data.k8s.allowed_capabilities as ["NET_BIND_SERVICE", "NET_RAW"]
}

# Nothing allowlisted means nothing added passes. An unloaded `data.k8s`
# collapses to this same empty set through the comprehension in security.rego,
# so a run that forgot `--data data/` fails loudly instead of approving
# SYS_ADMIN.
test_k8s_013_denies_every_addition_when_the_allowlist_never_loaded if {
	kubernetes.allowed_capabilities == set() with data.k8s as {}

	containers_flagged(fixtures.kubernetes["pod-adds-capability"], "K8S-013") == {"app", "init"} with data.k8s as {}
}

# K8S-014

test_k8s_014_denies_a_host_port if {
	ids(fixtures.kubernetes["pod-host-port"]) == {"K8S-014"}
	containers_flagged(fixtures.kubernetes["pod-host-port"], "K8S-014") == {"app"}

	messages(fixtures.kubernetes["pod-host-port"], "K8S-014") == {`container "app" binds hostPort 8080`}
}

# `hostPort: 0` is how the API server spells "unset", so it binds nothing and
# must not be reported — the same explicit-zero trap as `privileged: false`.
test_k8s_014_allows_host_port_zero if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {"containers": [{
			"name": "app",
			"ports": [{"containerPort": 8080, "hostPort": 0}],
		}]},
	}

	not "K8S-014" in ids(pod)
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
