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
	name in {null, "", "default"}
}

# K8S-010: pods on the default ServiceAccount must explicitly opt out of token
# mounting. An omitted value defaults to true at the API server.
deny contains msg if {
	default_service_account
	object.get(lib.pod_spec, "automountServiceAccountToken", true) != false

	msg := lib.finding(
		"K8S-010",
		"medium",
		"pod does not set automountServiceAccountToken: false for the default ServiceAccount",
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
