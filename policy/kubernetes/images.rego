# Image provenance policies over rendered Kubernetes manifests.
package kubernetes

import data.kubernetes.lib
import rego.v1

# The allowlist K8S-006 checks against, read from
# data/k8s.yaml. Adding a registry is a data change and touches
# no Rego.
#
# The comprehension is load-bearing, not just a list-to-set conversion. Testing
# `not registry in data.k8s.approved_registries` directly passes every image when
# that data was never loaded — a run that forgot `--data data/` goes green
# instead of red. Comprehending over the same undefined reference yields an
# empty set, so an absent allowlist approves nothing and the check fails closed.
approved_registries := {registry | some registry in data.k8s.approved_registries}

# K8S-006: images must come from an approved registry.
deny contains msg if {
	some container in lib.containers
	registry := lib.image_registry(container.image)
	not registry in approved_registries

	msg := lib.container_finding(
		"K8S-006",
		"high",
		container,
		sprintf("container %q pulls from unapproved registry %q", [container.name, registry]),
	)
}

# K8S-007: images must not ride the `latest` tag.
deny contains msg if {
	some container in lib.containers
	lib.image_tag(container.image) == "latest"

	msg := lib.container_finding(
		"K8S-007",
		"medium",
		container,
		sprintf(`container %q uses the mutable tag "latest"`, [container.name]),
	)
}

# K8S-007: an image with neither tag nor digest resolves to `latest` at pull
# time, so it is the same defect in different syntax and carries the same ID. A
# digest pin is the one immutable form and is accepted in place of a tag.
deny contains msg if {
	some container in lib.containers
	container.image
	not lib.image_tag(container.image)
	not lib.image_digest(container.image)

	msg := lib.container_finding(
		"K8S-007",
		"medium",
		container,
		sprintf("container %q pins neither a tag nor a digest", [container.name]),
	)
}
