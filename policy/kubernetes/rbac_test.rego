package kubernetes_test

import data.kubernetes
import rego.v1

test_k8s_016_denies_wildcards if {
	role := {"kind": "Role", "metadata": {"name": "r"}, "rules": [{"apiGroups": ["*"], "resources": ["pods"], "verbs": ["get"]}]}
	some msg in kubernetes.deny with input as role
	msg.id == "K8S-016"
}

test_k8s_017_denies_escalating_verbs if {
	role := {"kind": "ClusterRole", "metadata": {"name": "r"}, "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["escalate"]}]}
	some msg in kubernetes.deny with input as role
	msg.id == "K8S-017"
}

test_k8s_018_denies_cluster_secret_reads if {
	role := {"kind": "ClusterRole", "metadata": {"name": "r"}, "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]}
	some msg in kubernetes.deny with input as role
	msg.id == "K8S-018"
}

test_k8s_019_denies_cluster_admin_bindings if {
	binding := {"kind": "RoleBinding", "metadata": {"name": "b"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "name": "app"}]}
	some msg in kubernetes.deny with input as binding
	msg.id == "K8S-019"
}

test_k8s_019_allows_a_namespaced_role_named_cluster_admin if {
	binding := {"kind": "RoleBinding", "metadata": {"name": "b"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "name": "app"}]}
	not "K8S-019" in {msg.id | some msg in kubernetes.deny with input as binding}
}

test_k8s_019_allows_cluster_role_name_in_another_api_group if {
	binding := {"kind": "RoleBinding", "metadata": {"name": "b"}, "roleRef": {"apiGroup": "example.com", "kind": "ClusterRole", "name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "name": "app"}]}
	not "K8S-019" in {msg.id | some msg in kubernetes.deny with input as binding}
}

test_rbac_rules_ignore_workloads if {
	findings := kubernetes.deny with input as {"kind": "Pod", "metadata": {"name": "p"}, "spec": {"automountServiceAccountToken": false, "containers": []}}
	count(findings) == 0
}
