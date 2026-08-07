# Policy exceptions. Input is a consumer's `.platform-policy-exceptions.yaml`,
# not a manifest.
#
# This package only validates shape and expiry; scripts/apply-exceptions.sh does
# the suppression, reading `active` for the entries this package did not reject.
package exceptions

import rego.v1

required_fields := {"id", "owner", "ticket", "reason", "expires"}

# EXC-001: every entry must carry id, owner, ticket, reason, and expires. An
# entry without them cannot be audited later, so it fails closed.
deny contains msg if {
	some i, exc in input.exceptions
	some field in required_fields

	# `object.get` with a default is load-bearing: `not exc[field]` on a missing
	# key is undefined rather than true, silently dropping this rule.
	not is_string(object.get(exc, field, null))

	msg := {
		"id": "EXC-001",
		"severity": "medium",
		"enforcement": "deny",
		"resource": sprintf("exceptions[%d]", [i]),
		"msg": sprintf("exception is missing required field %q", [field]),
	}
}

# EXC-002: an id must name one rule. A wildcard turns a reviewed carve-out into
# a blanket suppression nobody signed off on.
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

# EXC-003: expires must be an ISO 8601 calendar date. A format Rego cannot parse
# cannot be checked for expiry, so it is rejected rather than never-expiring.
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

# EXC-004: an expired exception fails closed — this `deny` blocks the run rather
# than the entry quietly ceasing to suppress.
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

# EXC-005: exceptions are a short-lived break-glass mechanism. Limiting the
# window prevents a valid-looking entry from becoming a permanent waiver.
deny contains msg if {
	some i, exc in input.exceptions
	is_string(exc.expires)
	valid_date(exc.expires)
	time.parse_ns("2006-01-02", exc.expires) > time.now_ns() + 7776000000000000

	msg := {
		"id": "EXC-005",
		"severity": "high",
		"enforcement": "deny",
		"resource": sprintf("exceptions[%d]", [i]),
		"msg": sprintf("exception for %q expires more than 90 days from now", [object.get(exc, "id", "<unknown>")]),
	}
}

# An entry is usable only if no rule above denied it. Derived from `deny` rather
# than restating its conditions, so a new EXC-* rule disqualifies its entry the
# moment it is written.
rejected := {m.resource | some m in deny}

active contains exc if {
	some i, exc in input.exceptions
	not sprintf("exceptions[%d]", [i]) in rejected
}
