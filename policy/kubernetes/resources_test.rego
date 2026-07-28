package kubernetes_test

import data.fixtures
import data.kubernetes
import rego.v1

# K8S-005

test_k8s_005_denies_a_container_with_no_resources_block if {
	ids(fixtures.kubernetes["pod-missing-resources"]) == {"K8S-005"}
	containers_flagged(fixtures.kubernetes["pod-missing-resources"], "K8S-005") == {"app", "init"}
}

# The two containers in the fixture differ in how much they set, and the
# messages have to differ with them — a rule that reports "resources missing"
# without naming the paths makes a partial block indistinguishable from an
# absent one.
test_k8s_005_names_every_missing_path if {
	messages(fixtures.kubernetes["pod-missing-resources"], "K8S-005") == {
		`container "app" does not set resources.limits.cpu, resources.limits.memory, resources.requests.cpu, resources.requests.memory`,
		`container "init" does not set resources.limits.cpu, resources.limits.memory, resources.requests.memory`,
	}
}

test_k8s_005_allows_a_fully_specified_container if {
	not "K8S-005" in ids(fixtures.kubernetes["deployment-compliant"])
}

# A quantity of zero is a deliberate declaration — "this container needs no
# guaranteed CPU" — and is not the same as saying nothing. An absence check
# written as `not container.resources.requests.cpu` reads 0 as unset and
# reports a manifest that is in fact explicit.
test_k8s_005_treats_a_zero_quantity_as_declared if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"containers": [{
				"name": "app",
				"image": "registry.example.com/app:1.0.0",
				"resources": {
					"requests": {"cpu": 0, "memory": "64Mi"},
					"limits": {"cpu": "100m", "memory": "128Mi"},
				},
			}],
		},
	}

	not "K8S-005" in ids(pod)
}

test_k8s_005_reports_an_empty_resources_block_in_full if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {"containers": [{"name": "app", "resources": {}}]},
	}

	kubernetes.missing_quantities(pod.spec.containers[0]) == {
		"resources.requests.cpu",
		"resources.requests.memory",
		"resources.limits.cpu",
		"resources.limits.memory",
	}
}
