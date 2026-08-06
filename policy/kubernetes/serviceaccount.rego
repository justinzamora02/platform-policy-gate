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

# K8S-015: the other half of that resolution, read off the ServiceAccount
# document Conftest evaluates separately. `object.get` with a default of `true`
# because absent is the case the rule exists for — it means `true` at the API
# server, and a bare field reference would be undefined and drop the rule there.
deny contains msg if {
	input.kind == "ServiceAccount"
	object.get(input, "automountServiceAccountToken", true) != false

	msg := lib.finding(
		"K8S-015",
		"medium",
		"ServiceAccount does not set automountServiceAccountToken: false, so its token mounts by default",
	)
}
