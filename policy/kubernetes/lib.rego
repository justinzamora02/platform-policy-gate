# Shared traversal for Kubernetes workloads.
package kubernetes.lib

import rego.v1

# The PodSpec for this document, wherever its kind nests it. Undefined for every
# other kind, which is what keeps these policies inert against the Services and
# ConfigMaps rendered alongside.
pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job"}

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

# Regular and init containers as one set; init containers run with the same
# privileges as the rest of the pod.
containers contains container if {
	some field in ["containers", "initContainers"]
	some container in pod_spec[field]
}

# A securityContext field resolved with pod-level inheritance. Both levels are
# read through `object.get` so an explicit `false` on the container is a value,
# not an absent key a `true` on the pod can rescue.
inherited_security_context(container, field) := object.get(
	container,
	["securityContext", field],
	object.get(pod_spec, ["securityContext", field], null),
)

# The registry an image reference pulls from, defaulting to Docker Hub. The
# first path component counts only when it looks like a host, or `nginx:latest`
# parses as a registry named `nginx:latest`.
image_registry(image) := registry if {
	parts := split(image, "/")
	count(parts) > 1
	registry_host(parts[0])
	registry := parts[0]
} else := "docker.io"

registry_host(candidate) if contains(candidate, ".")

registry_host(candidate) if contains(candidate, ":")

registry_host(candidate) if candidate == "localhost"

# The tag on an image reference; undefined when it carries none. Splitting only
# the last path component keeps a registry port from reading as a tag, and the
# digest guard keeps `app@sha256:abc…` from doing the same.
image_tag(image) := tag if {
	not contains(image, "@")
	parts := split(image, "/")
	[_, tag] := split(parts[count(parts) - 1], ":")
}

# The digest an image reference pins to; undefined when it pins none.
image_digest(image) := digest if {
	[_, digest] := split(image, "@")
}

resource := sprintf("%s/%s", [input.kind, resource_name])

resource_name := name if {
	name := object.get(input, ["metadata", "name"], "")
	is_string(name)
	trim_space(name) != ""
} else := generate_name if {
	generate_name := object.get(input, ["metadata", "generateName"], "")
	is_string(generate_name)
	trim_space(generate_name) != ""
} else := "(unnamed)"

# Conftest requires the human-readable text under `msg` and surfaces every other
# key under `metadata`, which the aggregation step consumes.
finding(id, severity, message) := {
	"id": id,
	"severity": severity,
	"enforcement": "deny",
	"resource": resource,
	"msg": message,
}

container_finding(id, severity, container, message) := object.union(
	finding(id, severity, message),
	{"container": container.name},
)
