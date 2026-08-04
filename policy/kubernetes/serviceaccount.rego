# Workload identity policies over rendered Kubernetes manifests.
#
# Kept out of security.rego because the subject is the pod's ServiceAccount
# binding rather than its securityContext, and because the reasoning about what
# "the default ServiceAccount" means needs room that would bury the four
# securityContext rules it would otherwise sit among.
package kubernetes

import data.kubernetes.lib
import rego.v1

# Whether this pod runs under its namespace's default ServiceAccount.
#
# Three spellings reach the same binding: the field omitted, set to "default",
# or set through the deprecated `serviceAccount` alias the API server still
# mirrors onto `serviceAccountName`. Omission is the case that matters most —
# almost no manifest names the default SA explicitly, so a rule testing only
# `serviceAccountName == "default"` would miss nearly every pod actually bound
# to it.
default_service_account if {
	name := object.get(
		lib.pod_spec,
		"serviceAccountName",
		object.get(lib.pod_spec, "serviceAccount", "default"),
	)
	name in {"", "default"}
}

# K8S-010: pods on the default ServiceAccount must not mount its token.
#
# The default SA is shared by everything in the namespace that never asked for
# an identity, so its token is the one credential a compromised container should
# not be handed — and with nothing to audit, nobody notices it was mounted.
#
# Scoped to an explicit pod-level `true` on purpose. Automount resolves from two
# documents — the pod spec and the ServiceAccount object, pod winning — and
# Conftest evaluates one rendered document at a time, so the ServiceAccount's
# own setting is out of reach here. A pod that says nothing is therefore left to
# that setting rather than guessed at; what this rule catches is a manifest that
# reaches past it to mount the token of an identity nobody scoped.
deny contains msg if {
	lib.pod_spec.automountServiceAccountToken == true
	default_service_account

	msg := lib.finding(
		"K8S-010",
		"medium",
		"pod mounts the default ServiceAccount token (automountServiceAccountToken: true)",
	)
}
