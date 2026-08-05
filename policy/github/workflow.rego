# GitHub Actions workflow policies.
#
# Input is a single workflow document from `.github/workflows/`.
#
# GHA-001 overlaps with Zizmor on purpose. It is implemented here to show the
# parsing — Zizmor owns the deeper analysis (injection, permissions, artifact
# poisoning), and this package does not attempt any of it.
package github

import rego.v1

# --- workflow detection ---------------------------------------------------

# Workflows key their trigger block `on:`, which YAML 1.1 resolves to the
# boolean `true`. So the key that actually arrives depends on the parser:
#
#   "on"     a YAML 1.2 parser, or a workflow that quotes the key
#   "true"   Conftest and `opa test` — the YAML 1.1 boolean survives the
#            conversion to JSON, where every object key must be a string
#            (verify with `conftest parse` on any workflow)
#   true     input handed to OPA as native Rego, which allows non-string keys
#
# Accepting all three is the difference between a policy that runs and one that
# silently matches nothing. The failure mode is a green check, so it is worth
# the three lines.
has_trigger_block if input.on

has_trigger_block if input["true"]

has_trigger_block if input[true]

# Conftest hands this package every YAML file it was pointed at. Only documents
# that look like workflows are in scope; anything else evaluates to no findings
# rather than to nonsense findings.
is_workflow if {
	has_trigger_block
	is_object(input.jobs)
}

# --- action references ----------------------------------------------------

# Every `uses:` in the workflow, tagged with where it lives so a finding can
# name it. Reusable-workflow calls (`jobs.<id>.uses`) are action references
# under the same supply-chain argument, so they go in the same set.
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

# Actions in the caller's own repository are reviewed with the repository, so
# they carry no third-party risk and no ref to pin.
is_local(uses) if startswith(uses, "./")

# Splits `owner/repo@ref` and `owner/repo/path@ref`. Undefined for anything
# that is not an action reference (a bare `docker://` image, a `uses:` with no
# ref at all) — callers treat undefined as "cannot be vouched for".
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

# GHA-002: actions must appear in the allowlist. Undefined `data.gha.approved_actions`
# denies everything rather than allowing everything — an allowlist that fails
# open is not an allowlist.
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

# The message names the string a reviewer would add to data/gha.yaml, which is
# `owner/repo` — not the subpath-and-ref form the workflow wrote. Kept out of
# the rule body on purpose: `parsed()` is undefined for a reference with no ref
# at all, and a rule body that depended on it would stop denying exactly the
# references that cannot be vouched for. So this is total, and a reference it
# cannot split names itself.
allowlist_key(uses) := p.action if p := parsed(uses)

allowlist_key(uses) := uses if not parsed(uses)

# GHA-003: every runner label must be approved. Checking each label rather than
# the whole `runs-on` value stops a self-hosted runner from riding along as an
# extra label next to an approved one.
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

# `runs-on` is a string, a list of labels, or `{group, labels}`.
runner_labels(job) := {job["runs-on"]} if is_string(job["runs-on"])

runner_labels(job) := {label | some label in job["runs-on"]} if is_array(job["runs-on"])

runner_labels(job) := {label | some label in job["runs-on"].labels} if is_object(job["runs-on"])
