# Policy exceptions. Input is a consumer's `.platform-policy-exceptions.yaml`,
# not a manifest.
#
# This package only validates shape and expiry; scripts/apply-exceptions.sh does
# the suppression, reading `active` for the entries this package did not reject.
package exceptions

import rego.v1

required_fields := {"id", "owner", "ticket", "reason", "expires"}

# EXC-001: an exceptions file must be a list of auditable exception objects.
# Other shapes cannot be safely interpreted by the suppression script.
deny contains msg if {
	not has_exception_array

	msg := {
		"id": "EXC-001",
		"severity": "medium",
		"enforcement": "deny",
		"resource": "exceptions",
		"msg": "exceptions must be an array",
	}
}

deny contains msg if {
	has_exception_array
	some i, exc in input.exceptions
	not is_object(exc)

	msg := {
		"id": "EXC-001",
		"severity": "medium",
		"enforcement": "deny",
		"resource": sprintf("exceptions[%d]", [i]),
		"msg": "exception must be an object",
	}
}

deny contains msg if {
	has_exception_array
	some i, exc in input.exceptions
	is_object(exc)
	some field in required_fields

	# `object.get` with a default is load-bearing: `not exc[field]` on a missing
	# key is undefined rather than true, silently dropping this rule.
	not valid_required_field(object.get(exc, field, null))

	msg := {
		"id": "EXC-001",
		"severity": "medium",
		"enforcement": "deny",
		"resource": sprintf("exceptions[%d]", [i]),
		"msg": sprintf("exception is missing or blank required field %q", [field]),
	}
}

has_exception_array if {
	is_object(input)
	is_array(object.get(input, "exceptions", null))
}

valid_required_field(value) if {
	is_string(value)
	trim_space(value) != ""
}

# EXC-002: an id must name one rule. A wildcard turns a reviewed carve-out into
# a blanket suppression nobody signed off on.
deny contains msg if {
	has_exception_array
	some i, exc in input.exceptions
	is_object(exc)
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
	has_exception_array
	some i, exc in input.exceptions
	is_object(exc)
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
	has_exception_array
	some i, exc in input.exceptions
	is_object(exc)
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
	has_exception_array
	some i, exc in input.exceptions
	is_object(exc)
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
	has_exception_array
	some i, exc in input.exceptions
	is_object(exc)
	not sprintf("exceptions[%d]", [i]) in rejected
}
