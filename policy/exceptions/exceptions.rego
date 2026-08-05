# Policy exceptions.
#
# Input is a consumer's `.platform-policy-exceptions.yaml`, not a manifest:
#
#   exceptions:
#     - id: K8S-006
#       resource: Deployment/legacy-app
#       owner: platform-team
#       ticket: JIRA-123
#       reason: registry migration in progress
#       expires: 2026-12-31
#
# `resource` is optional and, when absent, suppresses every finding for that
# rule ID rather than one — a broader grant, which is why owner/ticket/reason
# are mandatory on every entry regardless of scope.
#
# This package only validates shape and expiry; scripts/apply-exceptions.sh
# does the suppression, using `exceptions.active` for the entries this package
# did not reject.
package exceptions

import rego.v1

required_fields := {"id", "owner", "ticket", "reason", "expires"}

# EXC-001: every entry must carry id, owner, ticket, reason, and expires.
# Missing context is what makes an exception impossible to audit later, so
# it is rejected the same way an expired one is — fail closed, not silently
# accepted with blank context.
deny contains msg if {
	some i, exc in input.exceptions
	some field in required_fields

	# `object.get` with a default is load-bearing: `exc[field]` on a missing
	# key is undefined, and `not` on an undefined expression is itself
	# undefined rather than true — it would silently drop this rule instead of
	# firing on the exact case (a missing field) it exists to catch.
	not is_string(object.get(exc, field, null))

	msg := {
		"id": "EXC-001",
		"severity": "medium",
		"enforcement": "deny",
		"resource": sprintf("exceptions[%d]", [i]),
		"msg": sprintf("exception is missing required field %q", [field]),
	}
}

# EXC-002: a rule ID naming a specific rule, not a family of them. An
# exception is a documented, reviewed carve-out for one violation — a wildcard
# turns it into a blanket suppression no reviewer signed off on.
deny contains msg if {
	some i, exc in input.exceptions
	is_string(exc.id)
	regex.match(`[*?]`, exc.id)

	msg := {
		"id": "EXC-002",
		"severity": "high",
		"enforcement": "deny",
		"resource": sprintf("exceptions[%d]", [i]),
		"msg": sprintf("exception id %q is a wildcard; exceptions must name one rule", [exc.id]),
	}
}

# EXC-003: expires must be an ISO 8601 calendar date. A format Rego cannot
# parse cannot be checked for expiry, so it is rejected here rather than
# silently treated as never-expiring.
deny contains msg if {
	some i, exc in input.exceptions
	is_string(exc.expires)
	not valid_date(exc.expires)

	msg := {
		"id": "EXC-003",
		"severity": "medium",
		"enforcement": "deny",
		"resource": sprintf("exceptions[%d]", [i]),
		"msg": sprintf("exception expires %q is not a YYYY-MM-DD date", [exc.expires]),
	}
}

valid_date(value) if {
	regex.match(`^\d{4}-\d{2}-\d{2}$`, value)
	time.parse_ns("2006-01-02", value)
}

# EXC-004: an expired exception fails closed. Once a `deny` here reaches the
# aggregated summary it blocks the run — the same as if the exception did not
# exist — rather than quietly stopping suppression while everything else stays
# green.
deny contains msg if {
	some i, exc in input.exceptions
	is_string(exc.expires)
	valid_date(exc.expires)
	expired(exc.expires)

	msg := {
		"id": "EXC-004",
		"severity": "high",
		"enforcement": "deny",
		"resource": sprintf("exceptions[%d]", [i]),
		"msg": sprintf("exception for %q expired on %q", [object.get(exc, "id", "<unknown>"), exc.expires]),
	}
}

expired(date) if time.parse_ns("2006-01-02", date) < time.now_ns()

# An entry is usable for suppression only once it has cleared every check
# above — invalid shape, a wildcard id, or an unparsed/expired date all
# disqualify it independently of one another.
invalid(exc) if {
	some field in required_fields
	not is_string(object.get(exc, field, null))
}

invalid(exc) if {
	is_string(exc.id)
	regex.match(`[*?]`, exc.id)
}

invalid(exc) if {
	is_string(exc.expires)
	not valid_date(exc.expires)
}

invalid(exc) if {
	is_string(exc.expires)
	valid_date(exc.expires)
	expired(exc.expires)
}

active contains exc if {
	some exc in input.exceptions
	not invalid(exc)
}
