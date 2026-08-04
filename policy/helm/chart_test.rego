package helm_test

import data.fixtures
import data.helm
import rego.v1

# Exact ID sets make each fixture document which rule owns its verdict.
ids(fixture) := {msg.id | some msg in helm.deny with input as fixture}

test_helm_rules_allow_complete_chart_metadata if {
	ids(fixtures.helm.compliant) == set()
}

test_helm_001_denies_missing_maintainers if {
	ids(fixtures.helm["missing-maintainers"]) == {"HELM-001"}
}

test_helm_002_denies_missing_description if {
	ids(fixtures.helm["missing-description"]) == {"HELM-002"}
}

test_helm_003_denies_invalid_semver if {
	ids(fixtures.helm["invalid-version"]) == {"HELM-003"}
}

# A parsed Dockerfile is an array, while an inventory has only `files`; neither
# has the root apiVersion/name pair that scopes Chart.yaml. Both must remain
# silent because Conftest evaluates this package against them anyway.
test_foreign_documents_are_out_of_scope if {
	ids(fixtures.dockerfile.compliant) == set()
	ids(fixtures.repo["license-present"]) == set()
}

test_findings_are_structured if {
	some msg in helm.deny with input as fixtures.helm["invalid-version"]
	msg.id == "HELM-003"
	msg.severity == "medium"
	msg.enforcement == "deny"
	msg.resource == "Chart/compliant-chart"
	is_string(msg.msg)
}
