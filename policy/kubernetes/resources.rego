# Resource governance over rendered Kubernetes manifests.
package kubernetes

import data.kubernetes.lib
import rego.v1

# The `resources.<section>.<dimension>` paths a container leaves unset. A set of
# paths rather than a boolean, so a partial block reports only its gaps and the
# finding can name exactly what to add.
missing_quantities(container) := {path |
	some section in ["requests", "limits"]
	some dimension in ["cpu", "memory"]
	object.get(container, ["resources", section, dimension], null) == null
	path := sprintf("resources.%s.%s", [section, dimension])
}

# K8S-005: containers must declare CPU and memory requests and limits. One
# finding per container listing every gap, not one finding per gap.
deny contains msg if {
	some container in lib.containers
	missing := missing_quantities(container)
	count(missing) > 0

	msg := lib.container_finding(
		"K8S-005",
		"medium",
		container,
		sprintf("container %q does not set %s", [container.name, concat(", ", sort(missing))]),
	)
}
