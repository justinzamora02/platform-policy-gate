# Image provenance policies over rendered Kubernetes manifests.
package kubernetes

import data.kubernetes.lib
import rego.v1

# The allowlist K8S-006 checks against, from data/k8s.yaml. The comprehension is
# load-bearing: a direct `not registry in data...` test passes every image when
# that data never loaded, where an empty set approves nothing.
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
# time — the same defect in different syntax. A digest is accepted as a pin.
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
