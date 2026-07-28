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
