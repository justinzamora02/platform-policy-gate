# Pod and container security policies over rendered Kubernetes manifests.
#
# Split by theme rather than collected into one kubernetes.rego: later PRs add
# resource-limit and image-provenance rules to this same package, and a single
# file holding all ten would stop being readable well before then.
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

# K8S-002: containers must run as a non-root user.
#
# The setting inherits from the pod, so a container that says nothing is judged
# by the pod's value; see lib.inherited_security_context for why an explicit
# `false` on the container is not rescued by a `true` on the pod.
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

# K8S-004: pods must not mount host paths.
#
# Detection keys off the presence of the `hostPath` block, not off its `path`;
# the path is only read for the message, and defaults, so a manifest missing the
# API-required field still gets reported instead of slipping through.
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

# K8S-008: containers must run with a read-only root filesystem.
#
# Read off the container alone, deliberately not through
# lib.inherited_security_context. `readOnlyRootFilesystem` exists on the
# container SecurityContext and has no counterpart on PodSecurityContext, so a
# pod-level value is inert — the kubelet never reads it. Inheriting it here
# would clear a container whose root filesystem the cluster still mounts
# writable, which is exactly the mistake a chart setting it one level too high
# makes.
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

# K8S-009: containers must drop every default capability.
#
# Container-only for the same reason as K8S-008, and more plainly so:
# `capabilities` has no pod-level counterpart at all, so there is nothing to
# inherit. The membership test is against the literal "ALL" because Kubernetes
# matches capability names exactly — a manifest dropping "all" drops nothing,
# and a case-insensitive check here would wave it through.
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

# Dropping "ALL" is the whole test; capabilities added back on top are a
# separate decision this rule does not judge. The `[]` default is what makes a
# container with no securityContext resolve to "drops nothing" instead of
# leaving the lookup undefined, which would make the negation above silent.
drops_all_capabilities(container) if {
	"ALL" in object.get(container, ["securityContext", "capabilities", "drop"], [])
}
