# GitHub Actions workflow policies. Input is a single workflow document from
# `.github/workflows/`.
#
# Zizmor owns the deeper analysis — template injection, artifact poisoning,
# dangerous triggers. The `permissions:` block (GHA-004) is owned here instead:
# it is decidable from the file alone, and Zizmor runs `--offline` in this
# gate. See docs/design.md § Workflow permissions.
package github

import rego.v1

# --- workflow detection ---------------------------------------------------

# `on:` is a YAML 1.1 boolean, so the trigger key arrives as "on", "true", or
# true depending on the parser. Matching only one silently matches nothing.
has_trigger_block if input.on

has_trigger_block if input["true"]

has_trigger_block if input[true]

# Conftest hands this package every YAML file it was pointed at, so anything
# that is not a workflow evaluates to no findings rather than nonsense ones.
is_workflow if {
	has_trigger_block
	is_object(input.jobs)
}

# --- action references ----------------------------------------------------

# Every `uses:` in the workflow, tagged with where it lives so a finding can
# name it. Reusable-workflow calls (`jobs.<id>.uses`) belong in the same set.
action_refs contains ref if {
	some job_id, job in input.jobs
	some i, step in job.steps
	ref := {
		"uses": step.uses,
		"resource": sprintf("jobs.%s.steps[%d]", [job_id, i]),
	}
}

action_refs contains ref if {
	some job_id, job in input.jobs
	ref := {
		"uses": job.uses,
		"resource": sprintf("jobs.%s", [job_id]),
	}
}

# Actions in the caller's own repository are reviewed with it, so they carry no
# third-party risk and no ref to pin.
is_local(uses) if startswith(uses, "./")

# Splits `owner/repo@ref` and `owner/repo/path@ref`. Undefined for anything that
# is not an action reference; callers read that as "cannot be vouched for".
parsed(uses) := {"action": action, "ref": ref} if {
	[path, ref] := split(uses, "@")
	segments := split(path, "/")
	count(segments) >= 2
	action := concat("/", array.slice(segments, 0, 2))
}

# --- rules ----------------------------------------------------------------

# GHA-001: third-party actions must be pinned to a full commit SHA. A tag is
# mutable; the account that owns the action can move it after review.
deny contains msg if {
	is_workflow
	some ref in action_refs
	not is_local(ref.uses)
	p := parsed(ref.uses)
	not sha_pinned(p.ref)

	msg := {
		"id": "GHA-001",
		"severity": "high",
		"enforcement": "deny",
		"resource": ref.resource,
		"action": ref.uses,
		"msg": sprintf("action %q is pinned to %q, not to a full commit SHA", [p.action, p.ref]),
	}
}

sha_pinned(ref) if regex.match(`^[0-9a-f]{40}$`, ref)

# GHA-002: actions must appear in the allowlist. An undefined
# `data.gha.approved_actions` denies everything rather than allowing everything.
deny contains msg if {
	is_workflow
	some ref in action_refs
	not is_local(ref.uses)
	not approved_action(ref.uses)

	msg := {
		"id": "GHA-002",
		"severity": "medium",
		"enforcement": "deny",
		"resource": ref.resource,
		"action": ref.uses,
		"msg": sprintf("action %q is not in the approved_actions list in data/gha.yaml", [allowlist_key(ref.uses)]),
	}
}

approved_action(uses) if parsed(uses).action in data.gha.approved_actions

# The message names the string a reviewer would add to data/gha.yaml
# (`owner/repo`), not the subpath-and-ref form the workflow wrote. Kept out of
# the rule body: `parsed()` is undefined for a reference with no ref at all, and
# a body depending on it would stop denying exactly what cannot be vouched for.
allowlist_key(uses) := p.action if p := parsed(uses)

allowlist_key(uses) := uses if not parsed(uses)

# GHA-003: every runner label must be approved. Per label, not per `runs-on`
# value, so a self-hosted runner cannot ride along next to an approved one.
deny contains msg if {
	is_workflow
	some job_id, job in input.jobs
	some label in runner_labels(job)
	not label in data.gha.approved_runners

	msg := {
		"id": "GHA-003",
		"severity": "medium",
		"enforcement": "deny",
		"resource": sprintf("jobs.%s", [job_id]),
		"runner": label,
		"msg": sprintf("runner label %q is not in the approved_runners list in data/gha.yaml", [label]),
	}
}

# A runner group cannot be checked without a separate allowlist. Reject a
# group-only selector instead of treating its absent labels as approved.
deny contains msg if {
	is_workflow
	some job_id, job in input.jobs
	group_only_runner(job)

	msg := {
		"id": "GHA-003",
		"severity": "medium",
		"enforcement": "deny",
		"resource": sprintf("jobs.%s", [job_id]),
		"runner": job["runs-on"].group,
		"msg": sprintf("runner group %q cannot be approved without runner labels", [job["runs-on"].group]),
	}
}

# `runs-on` is a string, a list of labels, or `{group, labels}`.
runner_labels(job) := {job["runs-on"]} if is_string(job["runs-on"])

runner_labels(job) := {label | some label in job["runs-on"]} if is_array(job["runs-on"])

runner_labels(job) := {label | some label in job["runs-on"].labels} if {
	is_object(job["runs-on"])
	is_array(job["runs-on"].labels)
}

runner_labels(job) := {job["runs-on"].labels} if {
	is_object(job["runs-on"])
	is_string(job["runs-on"].labels)
}

group_only_runner(job) if {
	is_object(job["runs-on"])
	is_string(object.get(job["runs-on"], "group", null))
	count(object.get(job["runs-on"], "labels", [])) == 0
}

# GHA-004: implicit permissions are broader than a workflow's reviewed intent,
# and `write-all` grants every available token scope. Require an explicit map;
# individual write scopes remain reviewable because some workflows need them.
deny contains msg if {
	is_workflow
	not input.permissions

	msg := {
		"id": "GHA-004",
		"severity": "high",
		"enforcement": "deny",
		"resource": "permissions",
		"msg": "workflow must declare an explicit permissions block",
	}
}

deny contains msg if {
	is_workflow
	input.permissions == "write-all"

	msg := {
		"id": "GHA-004",
		"severity": "high",
		"enforcement": "deny",
		"resource": "permissions",
		"msg": "workflow must not grant permissions: write-all",
	}
}

deny contains msg if {
	is_workflow
	some job_id, job in input.jobs
	job.permissions == "write-all"

	msg := {
		"id": "GHA-004",
		"severity": "high",
		"enforcement": "deny",
		"resource": sprintf("jobs.%s.permissions", [job_id]),
		"msg": "job must not grant permissions: write-all",
	}
}
