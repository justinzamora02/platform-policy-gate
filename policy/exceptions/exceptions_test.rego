package exceptions_test

import data.exceptions
import data.fixtures
import rego.v1

ids(fixture) := out if {
	msgs := exceptions.deny with input as fixture with time.now_ns as frozen_now_ns
	out := {msg.id | some msg in msgs}
}

active(fixture) := out if {
	out := exceptions.active with input as fixture with time.now_ns as frozen_now_ns
}

frozen_now_ns := time.parse_ns("2006-01-02", "2026-08-01")

test_valid_exception_has_no_findings if {
	ids(fixtures.exceptions.valid) == set()
}

test_valid_exception_is_active if {
	active(fixtures.exceptions.valid) == {fixtures.exceptions.valid.exceptions[0]}
}

test_exc_001_denies_missing_exceptions_array if {
	ids({}) == {"EXC-001"}
}

test_exc_001_denies_scalar_root if {
	ids("not-an-exceptions-file") == {"EXC-001"}
}

test_exc_001_denies_non_array_exceptions if {
	ids({"exceptions": {}}) == {"EXC-001"}
}

test_exc_001_denies_scalar_entry if {
	ids({"exceptions": ["K8S-006"]}) == {"EXC-001"}
}

test_exc_001_denies_blank_required_field if {
	fixture := object.union(fixtures.exceptions.valid, {"exceptions": [object.union(fixtures.exceptions.valid.exceptions[0], {"ticket": ""})]})
	ids(fixture) == {"EXC-001"}
}

test_exc_001_denies_whitespace_only_required_field if {
	fixture := object.union(fixtures.exceptions.valid, {"exceptions": [object.union(fixtures.exceptions.valid.exceptions[0], {"reason": " \t"})]})
	ids(fixture) == {"EXC-001"}
}

test_exc_001_denies_missing_required_field if {
	ids(fixtures.exceptions["missing-field"]) == {"EXC-001"}
}

test_exc_001_disqualifies_the_entry_from_active if {
	active(fixtures.exceptions["missing-field"]) == set()
}

test_exc_002_denies_wildcard_id if {
	ids(fixtures.exceptions["wildcard-id"]) == {"EXC-002"}
}

test_exc_002_disqualifies_the_entry_from_active if {
	active(fixtures.exceptions["wildcard-id"]) == set()
}

test_exc_003_denies_unparseable_expiry if {
	ids(fixtures.exceptions["bad-date-format"]) == {"EXC-003"}
}

test_exc_003_disqualifies_the_entry_from_active if {
	active(fixtures.exceptions["bad-date-format"]) == set()
}

test_exc_004_denies_expired_exception if {
	ids(fixtures.exceptions.expired) == {"EXC-004"}
}

test_exc_004_disqualifies_the_entry_from_active if {
	active(fixtures.exceptions.expired) == set()
}

test_exc_005_denies_an_exception_more_than_90_days_out if {
	ids(fixtures.exceptions["too-far-out"]) == {"EXC-005"}
}

test_exc_005_disqualifies_the_entry_from_active if {
	active(fixtures.exceptions["too-far-out"]) == set()
}

# Each entry is judged independently: one expired sibling does not disqualify
# a valid entry, and does not stop its own EXC-004 from firing.
test_mixed_file_reports_only_the_bad_entry if {
	ids(fixtures.exceptions.mixed) == {"EXC-004"}
}

test_mixed_file_keeps_the_valid_entry_active if {
	active(fixtures.exceptions.mixed) == {fixtures.exceptions.mixed.exceptions[0]}
}

test_findings_are_structured if {
	some msg in exceptions.deny with input as fixtures.exceptions["missing-field"]
	msg.severity in {"medium", "high"}
	msg.enforcement == "deny"
	is_string(msg.resource)
	is_string(msg.msg)
}
