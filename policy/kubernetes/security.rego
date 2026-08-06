# Pod and container security policies over rendered Kubernetes manifests.
package kubernetes

import data.kubernetes.lib
import rego.v1

# K8S-001: containers must not run privileged.
deny contains msg if {
	some container in lib.containers
	container.securityContext.privileged == true

	msg := lib.container_finding(
		"K8S-001",
		"high",
		container,
		sprintf("container %q runs privileged", [container.name]),
	)
}

# K8S-002: containers must run as a non-root user. Inherits from the pod.
deny contains msg if {
	some container in lib.containers
	lib.inherited_security_context(container, "runAsNonRoot") != true

	msg := lib.container_finding(
		"K8S-002",
		"high",
		container,
		sprintf("container %q does not run as non-root", [container.name]),
	)
}

# K8S-003: pods must not join a host namespace.
deny contains msg if {
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	lib.pod_spec[field] == true

	msg := lib.finding(
		"K8S-003",
		"high",
		sprintf("pod sets %s: true", [field]),
	)
}

# K8S-004: pods must not mount host paths. Keyed off the `hostPath` block, not
# its `path`, so a manifest missing the API-required field still reports.
deny contains msg if {
	some volume in lib.pod_spec.volumes
	volume.hostPath

	msg := lib.finding(
		"K8S-004",
		"high",
		sprintf(
			"volume %q mounts host path %q",
			[volume.name, object.get(volume, ["hostPath", "path"], "(unspecified)")],
		),
	)
}

# K8S-008: containers must run with a read-only root filesystem. Read off the
# container alone — the field has no PodSecurityContext counterpart, so a
# pod-level value is inert and inheriting it would clear a writable container.
deny contains msg if {
	some container in lib.containers
	object.get(container, ["securityContext", "readOnlyRootFilesystem"], null) != true

	msg := lib.container_finding(
		"K8S-008",
		"medium",
		container,
		sprintf("container %q does not set readOnlyRootFilesystem: true", [container.name]),
	)
}

# K8S-009: containers must drop every default capability. Container-only for the
# same reason as K8S-008.
deny contains msg if {
	some container in lib.containers
	not drops_all_capabilities(container)

	msg := lib.container_finding(
		"K8S-009",
		"high",
		container,
		sprintf("container %q does not drop capability ALL", [container.name]),
	)
}

# Kubernetes matches capability names exactly, so the test is against the
# literal "ALL". The `[]` default keeps a missing securityContext resolving to
# "drops nothing" rather than leaving the negation above undefined.
drops_all_capabilities(container) if {
	"ALL" in object.get(container, ["securityContext", "capabilities", "drop"], [])
}

# The allowlist K8S-013 checks against, from data/k8s.yaml. The comprehension is
# load-bearing for the same reason it is in images.rego: a direct `not capability
# in data...` test approves every addition when that data never loaded.
allowed_capabilities := {capability | some capability in data.k8s.allowed_capabilities}

# The capabilities a container adds that are not on the allowlist. A set rather
# than a boolean, so one finding can name every one of them. Names are compared
# exactly, as Kubernetes compares them: `sys_admin` is not `SYS_ADMIN`, and is
# denied for being off the list rather than normalised onto it.
disallowed_capabilities(container) := {capability |
	some capability in object.get(container, ["securityContext", "capabilities", "add"], [])
	not capability in allowed_capabilities
}

# K8S-013: capabilities added back must be on the allowlist. K8S-009 judges the
# drop alone, so `drop: [ALL]` with `add: [SYS_ADMIN]` satisfies it while handing
# the container most of root back. Container-only, same as K8S-009.
deny contains msg if {
	some container in lib.containers
	disallowed := disallowed_capabilities(container)
	count(disallowed) > 0

	msg := lib.container_finding(
		"K8S-013",
		"high",
		container,
		sprintf("container %q adds capability %s", [container.name, concat(", ", sort(disallowed))]),
	)
}

# K8S-014: containers must not bind a host port. A hostPort publishes on the
# node's network namespace, which NetworkPolicy does not govern. `hostPort: 0`
# is what the API server treats as unset, so it is not a binding.
deny contains msg if {
	some container in lib.containers
	some port in container.ports
	port.hostPort != 0

	msg := lib.container_finding(
		"K8S-014",
		"high",
		container,
		sprintf("container %q binds hostPort %v", [container.name, port.hostPort]),
	)
}
