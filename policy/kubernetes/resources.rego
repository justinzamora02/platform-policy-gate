# Resource governance over rendered Kubernetes manifests.
package kubernetes

import data.kubernetes.lib
import rego.v1

# The `resources.<section>.<dimension>` paths a container leaves unset.
#
# Built as a set of dotted paths rather than a boolean so the finding can name
# exactly what to add. `object.get` with a null default is what makes a partial
# block — requests but no limits, or CPU but no memory — report only its gaps
# instead of passing on the presence of `resources` alone.
missing_quantities(container) := {path |
	some section in ["requests", "limits"]
	some dimension in ["cpu", "memory"]
	object.get(container, ["resources", section, dimension], null) == null
	path := sprintf("resources.%s.%s", [section, dimension])
}

# K8S-005: containers must declare CPU and memory requests and limits.
#
# One finding per container listing every gap, rather than one finding per gap:
# a container with no `resources` block is a single mistake, and splitting it
# into four findings would crowd out the rest of the summary.
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
