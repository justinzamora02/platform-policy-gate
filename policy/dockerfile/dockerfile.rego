# Dockerfile base-image policies. Conftest's parser hands the package one array
# of instructions per file. Hadolint owns every instruction except FROM.
package dockerfile

import rego.v1

# A parsed Dockerfile always contains a FROM instruction with a numeric stage,
# which is what keeps the package silent on every other kind of document.
is_dockerfile if {
	is_array(input)
	some instruction in input
	instruction.Cmd == "from"
	is_array(instruction.Value)
	is_number(instruction.Stage)
}

# Stage aliases are local references, not images. Resolved before checking FROM
# values, or `FROM builder` reads as an untagged Docker Hub image.
stage_aliases := {lower(alias) |
	some instruction in input
	instruction.Cmd == "from"
	[_, marker, alias] := instruction.Value
	lower(marker) == "as"
}

external_stages contains stage if {
	is_dockerfile
	some instruction in input
	instruction.Cmd == "from"
	image := instruction.Value[0]
	not lower(image) in stage_aliases
	stage := {"image": image, "number": instruction.Stage}
}

# The first component is a registry only when it looks like a host, or
# `golang:1.22` reads as a registry named `golang:1.22`.
image_registry(image) := registry if {
	parts := split(image, "/")
	count(parts) > 1
	registry_host(parts[0])
	registry := parts[0]
} else := "docker.io"

registry_host(candidate) if contains(candidate, ".")

registry_host(candidate) if contains(candidate, ":")

registry_host(candidate) if candidate == "localhost"

# Reading only the last path component keeps a registry port from becoming a
# tag; the digest guard keeps `sha256:...` from doing the same.
image_tag(image) := tag if {
	not contains(image, "@")
	parts := split(image, "/")
	[_, tag] := split(parts[count(parts) - 1], ":")
}

image_digest(image) := digest if {
	[_, digest] := split(image, "@")
}

# The comprehension fails closed when data/docker.yaml was not loaded, where a
# direct negative membership test would pass every image.
approved_registries := {registry | some registry in data.docker.approved_registries}

finding(id, severity, stage, message) := {
	"id": id,
	"severity": severity,
	"enforcement": "deny",
	"resource": sprintf("Dockerfile stage %d", [stage]),
	"msg": message,
}

# DOCKER-001: external base images must come from an approved registry.
deny contains msg if {
	some stage in external_stages
	registry := image_registry(stage.image)
	not registry in approved_registries

	msg := finding(
		"DOCKER-001",
		"high",
		stage.number,
		sprintf("base image %q pulls from unapproved registry %q", [stage.image, registry]),
	)
}

# DOCKER-003: the final image stage must not inherit the daemon's root user.
# Only the last USER instruction in that stage matters because Docker applies
# instructions in order.
final_stage := max({instruction.Stage | some instruction in input; instruction.Cmd == "from"}) if is_dockerfile

final_user := value if {
	some index, instruction in input
	instruction.Cmd == "user"
	instruction.Stage == final_stage
	value := instruction.Value[0]
	not later_user(index)
}

later_user(index) if {
	some later, instruction in input
	later > index
	instruction.Cmd == "user"
	instruction.Stage == final_stage
}

deny contains msg if {
	is_dockerfile
	not final_user

	msg := finding(
		"DOCKER-003",
		"high",
		final_stage,
		"final image stage does not declare a non-root USER",
	)
}

deny contains msg if {
	is_dockerfile
	user := lower(split(sprintf("%v", [final_user]), ":")[0])
	user in {"root", "0"}

	msg := finding(
		"DOCKER-003",
		"high",
		final_stage,
		sprintf("final image stage runs as root user %q", [final_user]),
	)
}

# DOCKER-002: `latest` is mutable even when the registry is trusted.
deny contains msg if {
	some stage in external_stages
	image_tag(stage.image) == "latest"

	msg := finding(
		"DOCKER-002",
		"medium",
		stage.number,
		sprintf("base image %q uses the mutable tag \"latest\"", [stage.image]),
	)
}

# DOCKER-002: an image with neither tag nor digest resolves to `latest`. A
# digest is accepted as the immutable form.
deny contains msg if {
	some stage in external_stages
	not image_tag(stage.image)
	not image_digest(stage.image)

	msg := finding(
		"DOCKER-002",
		"medium",
		stage.number,
		sprintf("base image %q pins neither a tag nor a digest", [stage.image]),
	)
}
