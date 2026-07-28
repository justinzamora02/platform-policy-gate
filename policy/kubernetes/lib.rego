# Shared traversal for Kubernetes workloads.
#
# Conftest evaluates one rendered document at a time, so every rule reads
# `input` as a single manifest. The traversal exists because a PodSpec sits at a
# different depth per kind — bare on a Pod, one template down on a Deployment,
# StatefulSet, DaemonSet, ReplicaSet, or Job, and two down on a CronJob — and
# because containers live in two sibling lists. Resolving both here once keeps
# every rule a single `some container in lib.containers`.
package kubernetes.lib

import rego.v1

# The PodSpec for this document, wherever its kind nests it.
#
# Deliberately undefined for every other kind. That is what keeps these policies
# inert against the Services, ConfigMaps, and ServiceAccounts that come out of
# the same `helm template` run, rather than having each rule re-test the kind.
pod_spec := input.spec if input.kind == "Pod"

pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

# Regular and init containers, as one set.
#
# Init containers run with the same privileges as the rest of the pod, so every
# rule in this package applies to them identically; a policy set that only walks
# `spec.containers` misses half the attack surface. Names are unique across both
# lists, so collapsing them into a set loses nothing.
containers contains container if {
	some field in ["containers", "initContainers"]
	some container in pod_spec[field]
}

# A securityContext field resolved with pod-level inheritance.
#
# Reading both levels through `object.get` is what keeps an explicit `false` on
# the container from being rescued by a `true` on the pod: a plain
# "container value or else pod value" fallback treats an explicit `false` as
# absent and silently passes the container, which is the exact case an attacker
# would write. Returns null when neither level sets the field.
inherited_security_context(container, field) := object.get(
	container,
	["securityContext", field],
	object.get(pod_spec, ["securityContext", field], null),
)

# The registry an image reference pulls from, defaulting to Docker Hub.
#
# The first path component counts as the registry only when it looks like a
# host. Without that test `nginx:latest` parses as a registry named
# `nginx:latest` and `myorg/app` as one named `myorg`, when both actually come
# from docker.io — which is the registry an allowlist most needs to catch.
image_registry(image) := registry if {
	parts := split(image, "/")
	count(parts) > 1
	registry_host(parts[0])
	registry := parts[0]
} else := "docker.io"

registry_host(candidate) if contains(candidate, ".")

registry_host(candidate) if contains(candidate, ":")

registry_host(candidate) if candidate == "localhost"

# The tag on an image reference; undefined when it carries none.
#
# Splitting only the last path component is what keeps a registry port
# (`localhost:5000/app`) from being read as a tag, and the digest guard keeps
# the hex of `app@sha256:abc…` from being read as one.
image_tag(image) := tag if {
	not contains(image, "@")
	parts := split(image, "/")
	[_, tag] := split(parts[count(parts) - 1], ":")
}

# The digest an image reference pins to; undefined when it pins none.
image_digest(image) := digest if {
	[_, digest] := split(image, "@")
}

resource := sprintf("%s/%s", [input.kind, input.metadata.name])

# Every rule emits this shape rather than a bare string. Conftest requires the
# human-readable text under `msg` and surfaces every other key under `metadata`,
# which is what makes the aggregation step downstream possible.
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
