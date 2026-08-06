# RBAC least-privilege policies over rendered Kubernetes manifests.
package kubernetes

import data.kubernetes.lib
import rego.v1

# These kinds carry no PodSpec, so each rule guards on the kind itself where the
# workload rules lean on `lib.pod_spec` being undefined.
policy_rule_kinds := {"Role", "ClusterRole"}

# `escalate` grants permissions the subject does not hold, `bind` attaches an
# existing higher-privilege role, and `impersonate` acts as any user or group.
privilege_escalating_verbs := {"escalate", "bind", "impersonate"}

read_verbs := {"get", "list", "watch"}

# The fields of one PolicyRule that carry "*". `object.get` keeps an absent
# field out of the set instead of leaving the membership test undefined.
wildcard_fields(policy_rule) := {field |
	some field in ["apiGroups", "resources", "verbs"]
	"*" in object.get(policy_rule, field, [])
}

verbs_matching(policy_rule, candidates) := {verb |
	some verb in object.get(policy_rule, "verbs", [])
	verb in candidates
}

# K8S-016: a Role or ClusterRole must not grant "*". One finding per rule entry
# naming every wildcard field, not one finding per field.
deny contains msg if {
	input.kind in policy_rule_kinds
	some index, policy_rule in input.rules
	fields := wildcard_fields(policy_rule)
	count(fields) > 0

	msg := lib.finding(
		"K8S-016",
		"high",
		sprintf(`rules[%d] uses the wildcard "*" in %s`, [index, concat(", ", sort(fields))]),
	)
}

# K8S-017: a Role or ClusterRole must not grant escalate, bind, or impersonate.
# A wildcard verb is K8S-016's finding and is not repeated here.
deny contains msg if {
	input.kind in policy_rule_kinds
	some index, policy_rule in input.rules
	verbs := verbs_matching(policy_rule, privilege_escalating_verbs)
	count(verbs) > 0

	msg := lib.finding(
		"K8S-017",
		"high",
		sprintf("rules[%d] grants the privilege-escalating verbs %s", [index, concat(", ", sort(verbs))]),
	)
}

# K8S-018: a ClusterRole must not grant read access to secrets. Cluster-scoped
# only — a namespaced Role reaches one namespace's credentials, not every one.
deny contains msg if {
	input.kind == "ClusterRole"
	some index, policy_rule in input.rules
	"secrets" in object.get(policy_rule, "resources", [])
	core_api_group(policy_rule)
	verbs := verbs_matching(policy_rule, read_verbs)
	count(verbs) > 0

	msg := lib.finding(
		"K8S-018",
		"high",
		sprintf("rules[%d] grants cluster-wide %s on secrets", [index, concat(", ", sort(verbs))]),
	)
}

core_api_group(policy_rule) if "" in object.get(policy_rule, "apiGroups", [])

# An absent or empty `apiGroups` counts as the core group: such a rule matches
# nothing in Kubernetes, so denying it blocks no working grant, where reading it
# as "no group" would leave the one-character fix to `[""]` unreviewed.
core_api_group(policy_rule) if count(object.get(policy_rule, "apiGroups", [])) == 0

# K8S-019: nothing may be bound to cluster-admin. Kubernetes resolves
# `roleRef.name` exactly, so this compares exactly.
deny contains msg if {
	input.kind in {"RoleBinding", "ClusterRoleBinding"}
	input.roleRef.name == "cluster-admin"
	subjects := {sprintf("%s %q", [subject.kind, subject.name]) | some subject in object.get(input, "subjects", [])}

	msg := lib.finding(
		"K8S-019",
		"high",
		sprintf("binds cluster-admin to %s", [subject_list(subjects)]),
	)
}

subject_list(subjects) := concat(", ", sort(subjects)) if count(subjects) > 0

subject_list(subjects) := "no subjects" if count(subjects) == 0
