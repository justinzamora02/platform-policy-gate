package kubernetes_test

import data.fixtures
import data.kubernetes
import rego.v1

# K8S-006

test_k8s_006_denies_an_unapproved_registry if {
	ids(fixtures.kubernetes["pod-unapproved-registry"]) == {"K8S-006"}
	containers_flagged(fixtures.kubernetes["pod-unapproved-registry"], "K8S-006") == {"app", "init"}
}

# The bare `busybox:1.36` in the fixture has to be reported as docker.io, not
# as an image with no registry to check.
test_k8s_006_names_the_resolved_registry if {
	messages(fixtures.kubernetes["pod-unapproved-registry"], "K8S-006") == {
		`container "app" pulls from unapproved registry "quay.io"`,
		`container "init" pulls from unapproved registry "docker.io"`,
	}
}

test_k8s_006_allows_an_approved_registry if {
	not "K8S-006" in ids(fixtures.kubernetes["deployment-compliant"])
}

# The done-check for this PR: the same manifest flips verdict on the data file
# alone, with no edit to any rule.
test_k8s_006_verdict_follows_the_data_file if {
	pod := fixtures.kubernetes["pod-unapproved-registry"]

	containers_flagged(pod, "K8S-006") == {"app", "init"} with data.k8s.approved_registries as ["registry.example.com"]
	containers_flagged(pod, "K8S-006") == {"init"} with data.k8s.approved_registries as ["registry.example.com", "quay.io"]
	ids(pod) == set() with data.k8s.approved_registries as ["registry.example.com", "quay.io", "docker.io"]
}

# Nothing approved means nothing passes. An absent data file collapses to this
# same empty set through the comprehension in images.rego, which is how a run
# that forgot `--data data/` fails loudly instead of waving every image through.
test_k8s_006_denies_everything_when_the_allowlist_is_empty if {
	kubernetes.approved_registries == set() with data.k8s.approved_registries as []

	containers_flagged(fixtures.kubernetes["deployment-compliant"], "K8S-006") == {"app", "init"} with data.k8s.approved_registries as []
}

# K8S-007

test_k8s_007_denies_the_latest_tag if {
	ids(fixtures.kubernetes["pod-latest-tag"]) == {"K8S-007"}

	messages(fixtures.kubernetes["pod-latest-tag"], "K8S-007") == {`container "app" uses the mutable tag "latest"`}
}

test_k8s_007_denies_an_untagged_image if {
	ids(fixtures.kubernetes["pod-untagged-image"]) == {"K8S-007"}

	messages(fixtures.kubernetes["pod-untagged-image"], "K8S-007") == {`container "app" pins neither a tag nor a digest`}
}

# The digest-pinned init container in the same fixture is the immutable form and
# must stay silent, which is what separates this rule from "deny when there is
# no colon-tag".
test_k8s_007_allows_a_digest_pin if {
	containers_flagged(fixtures.kubernetes["pod-untagged-image"], "K8S-007") == {"app"}
}

test_k8s_007_allows_a_pinned_tag if {
	not "K8S-007" in ids(fixtures.kubernetes["deployment-compliant"])
}

# A registry port is a colon in the reference that is not a tag. Without the
# last-path-component split this image reads as tag `5000/app` and passes.
test_k8s_007_denies_an_untagged_image_behind_a_registry_port if {
	pod := {
		"kind": "Pod",
		"metadata": {"name": "p"},
		"spec": {"containers": [{"name": "app", "image": "localhost:5000/app"}]},
	}

	containers_flagged(pod, "K8S-007") == {"app"}
}
