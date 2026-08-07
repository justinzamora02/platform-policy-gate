# Node project policies. Input carries the root package.json manifest and the
# repository's tracked root files.
package node

import rego.v1

# Every field is part of the input contract. This keeps partial inventories and
# non-Node documents silent rather than producing unrelated findings.
is_node_project if {
	input.kind == "node-project"
	input.path == "package.json"
	is_object(input.manifest)
	is_array(input.tracked_files)
}

finding(id, severity, resource, message) := {
	"id": id,
	"severity": severity,
	"enforcement": "deny",
	"resource": resource,
	"msg": message,
}

package_manager := object.get(input.manifest, "packageManager", null)

exact_pnpm_version if {
	[manager, version] := split(package_manager, "@")
	manager == "pnpm"
	semver.is_valid(version)
}

node_constraint := object.get(engines, "node", null) if {
	engines := object.get(input.manifest, "engines", {})
	is_object(engines)
} else := null

# The comprehension keeps an unloaded data file from approving every value.
approved_constraints := {constraint | some constraint in data.node_policy.approved_node_constraints}

# NODE-001: Corepack needs an unambiguous pnpm release to activate.
deny contains msg if {
	is_node_project
	not exact_pnpm_version

	msg := finding(
		"NODE-001",
		"medium",
		"package.json",
		"packageManager must pin pnpm to an exact semantic version",
	)
}

# NODE-002: only approved canonical Node LTS constraints are allowed.
deny contains msg if {
	is_node_project
	not node_constraint in approved_constraints

	msg := finding(
		"NODE-002",
		"medium",
		"package.json",
		sprintf("engines.node %q is not an approved Node constraint", [node_constraint]),
	)
}

# NODE-003: pnpm's lockfile records the reviewed dependency graph.
deny contains msg if {
	is_node_project
	not "pnpm-lock.yaml" in input.tracked_files

	msg := finding(
		"NODE-003",
		"high",
		"pnpm-lock.yaml",
		"root pnpm-lock.yaml must be tracked",
	)
}

disallowed_lockfiles := {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb"}

# NODE-004: a root project has one package manager and one lockfile format.
deny contains msg if {
	is_node_project
	some file in input.tracked_files
	file in disallowed_lockfiles

	msg := finding(
		"NODE-004",
		"medium",
		file,
		sprintf("root lockfile %q is not allowed in a pnpm project", [file]),
	)
}
