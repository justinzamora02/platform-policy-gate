# Workload identity policies over rendered Kubernetes manifests.
package kubernetes

import data.kubernetes.lib
import rego.v1

# Whether this pod runs under its namespace's default ServiceAccount. Three
# spellings reach the same binding — the field omitted, set to "default", or set
# through the deprecated `serviceAccount` alias — and omission is the common one.
default_service_account if {
	name := object.get(
		lib.pod_spec,
		"serviceAccountName",
		object.get(lib.pod_spec, "serviceAccount", "default"),
	)
	name in {"", "default"}
}

# K8S-010: pods on the default ServiceAccount must not mount its token. Scoped
# to an explicit pod-level `true`, because automount also resolves from the
# ServiceAccount object, which Conftest cannot see from a single document.
deny contains msg if {
	lib.pod_spec.automountServiceAccountToken == true
	default_service_account

	msg := lib.finding(
		"K8S-010",
		"medium",
		"pod mounts the default ServiceAccount token (automountServiceAccountToken: true)",
	)
}
