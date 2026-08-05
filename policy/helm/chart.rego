# Helm chart metadata policies.
package helm

import rego.v1

# Chart.yaml keeps apiVersion and name at the document root, where a Kubernetes
# manifest puts its name under metadata — enough to tell the two apart.
is_chart if {
	input.apiVersion in {"v1", "v2"}
	is_string(input.name)
}

resource := sprintf("Chart/%s", [input.name])

finding(id, severity, message) := {
	"id": id,
	"severity": severity,
	"enforcement": "deny",
	"resource": resource,
	"msg": message,
}

has_maintainers if {
	is_array(input.maintainers)
	count(input.maintainers) > 0
}

has_description if {
	is_string(input.description)
	trim_space(input.description) != ""
}

has_semver_version if {
	is_string(input.version)
	semver.is_valid(input.version)
}

# HELM-001: charts must identify at least one maintainer.
deny contains msg if {
	is_chart
	not has_maintainers
	msg := finding("HELM-001", "medium", "Chart.yaml declares no maintainers")
}

# HELM-002: charts need a description for discovery and review tooling.
deny contains msg if {
	is_chart
	not has_description
	msg := finding("HELM-002", "low", "Chart.yaml declares no description")
}

# HELM-003: Helm orders and packages releases by this version, so a merely
# present string is insufficient.
deny contains msg if {
	is_chart
	not has_semver_version
	msg := finding("HELM-003", "medium", "Chart.yaml version is missing or is not valid semver")
}
