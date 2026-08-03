package kubernetes_test

import data.fixtures
import rego.v1

# A minimal pod carrying only what K8S-010 reads, so a case can name one field
# and mean it. Every container field is omitted deliberately: the rule is
# pod-scoped, and the other rules' findings are filtered out by `ids` here.
sa_pod(spec) := {
	"kind": "Pod",
	"metadata": {"name": "p"},
	"spec": spec,
}

# K8S-010

test_k8s_010_denies_automount_on_the_implicit_default_sa if {
	ids(fixtures.kubernetes["pod-default-sa-automount"]) == {"K8S-010"}

	messages(fixtures.kubernetes["pod-default-sa-automount"], "K8S-010") == {"pod mounts the default ServiceAccount token (automountServiceAccountToken: true)"}
}

test_k8s_010_allows_automount_on_a_named_sa if {
	ids(fixtures.kubernetes["pod-named-sa-automount"]) == set()
}

# The three spellings of the same binding. Naming the default SA explicitly and
# the deprecated `serviceAccount` alias are both rarer than omission, but all
# three land on the same shared identity.
test_k8s_010_recognises_every_spelling_of_the_default_sa if {
	every spec in [
		{"automountServiceAccountToken": true},
		{"automountServiceAccountToken": true, "serviceAccountName": "default"},
		{"automountServiceAccountToken": true, "serviceAccountName": ""},
		{"automountServiceAccountToken": true, "serviceAccount": "default"},
	] {
		"K8S-010" in ids(sa_pod(spec))
	}
}

# The deprecated alias naming a real SA must not be read as the default one.
test_k8s_010_honours_the_deprecated_alias_when_it_names_another_sa if {
	not "K8S-010" in ids(sa_pod({"automountServiceAccountToken": true, "serviceAccount": "reconciler"}))
}

# Silence on omission is the deliberate scope, not an oversight: automount also
# resolves from the ServiceAccount object, which is a different document than
# the one Conftest has in hand, so this rule has nothing to judge here.
test_k8s_010_is_silent_when_the_pod_does_not_set_automount if {
	not "K8S-010" in ids(sa_pod({"containers": [{"name": "app"}]}))
}

test_k8s_010_allows_automount_turned_off if {
	not "K8S-010" in ids(sa_pod({"automountServiceAccountToken": false}))
}
