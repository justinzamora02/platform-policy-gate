#!/usr/bin/env bash
# Exercise the same status, artifact, suppression, and aggregate path used by
# the reusable workflow without requiring a GitHub Actions runner.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixtures="$root/testdata/policy-check"

assert_success() {
	local output
	if ! output="$("$@" 2>&1)"; then
		echo "expected success: $*" >&2
		echo "$output" >&2
		exit 1
	fi
	printf '%s\n' "$output"
}

assert_failure() {
	local output
	if output="$("$@" 2>&1)"; then
		echo "expected failure: $*" >&2
		echo "$output" >&2
		exit 1
	fi
	printf '%s\n' "$output"
}

run_aggregate() {
	local arg
	for arg in "$@"; do
		if [[ "$arg" = discover-helm:* ]]; then
			bash "$root/scripts/aggregate-policy-check.sh" "$@"
			return
		fi
	done
	bash "$root/scripts/aggregate-policy-check.sh" "$@" discover-helm:success helm:skipped no-helm-charts:success
}

missing_exceptions="$fixtures/no-exceptions.yaml"

assert_success run_aggregate "$missing_exceptions" "$fixtures/empty-findings" kubernetes:success \
	| grep -F 'No findings.'
assert_failure run_aggregate "$missing_exceptions" "$fixtures/malformed-findings" kubernetes:success \
	| grep -F 'invalid normalized findings'
assert_success run_aggregate "$root/test/fixtures/exceptions/valid/exceptions.yaml" "$fixtures/suppressed-findings" kubernetes:success \
	| grep -F 'No findings.'
assert_success run_aggregate "$root/test/fixtures/exceptions/mixed/exceptions.yaml" "$fixtures/suppressed-findings" kubernetes:success \
	| grep -F 'No findings.'
assert_failure run_aggregate "$missing_exceptions" "$fixtures/deny-findings" kubernetes:success \
	| grep -F '### Deny (1)'
assert_success run_aggregate "$missing_exceptions" "$fixtures/warn-findings" kubernetes:success \
	| grep -F '### Warn (1)'
FAIL_ON_WARN=true assert_failure run_aggregate "$missing_exceptions" "$fixtures/warn-findings" kubernetes:success \
	| grep -F '### Warn (1)'
assert_failure run_aggregate "$missing_exceptions" "$fixtures/empty-artifact" kubernetes:success \
	| grep -F 'missing or empty findings artifact'
assert_failure run_aggregate "$missing_exceptions" "$fixtures/missing-artifact" kubernetes:success \
	| grep -F 'missing or empty findings artifact'
assert_failure run_aggregate "$missing_exceptions" "$fixtures/empty-findings" kubernetes:failure \
	| grep -F 'A policy leg ended with status: failure'
assert_failure run_aggregate "$missing_exceptions" "$fixtures/empty-findings" kubernetes:success discover-helm:failure helm:skipped no-helm-charts:success \
	| grep -F 'A policy leg ended with status: failure'
assert_failure run_aggregate "$missing_exceptions" "$fixtures/empty-findings" kubernetes:success discover-helm:success helm:skipped no-helm-charts:skipped \
	| grep -F 'exactly one Helm result must be success'

assert_success bash "$root/scripts/normalize-conftest.sh" "$fixtures/normalizers/conftest.json" \
	| jq -e 'length == 2 and .[0] == {id: "K8S-001", severity: "high", enforcement: "deny", file: "manifest.yaml", resource: "Deployment/api", msg: "privileged"} and .[1] == {id: "K8S-002", severity: "medium", enforcement: "warn", file: "manifest.yaml", resource: "Deployment/api", msg: "review"}'
assert_success bash "$root/scripts/normalize-hadolint.sh" "$fixtures/normalizers/hadolint.json" \
	| jq -e '. == [{id: "DL3000", severity: "medium", enforcement: "deny", file: "Dockerfile", resource: "line 2", msg: "Use an absolute workdir."}]'
assert_success bash "$root/scripts/normalize-zizmor.sh" "$fixtures/normalizers/zizmor.json" \
	| jq -e '. == [{id: "unpinned-uses", severity: "high", enforcement: "deny", file: ".github/workflows/test.yml", resource: "jobs.test.steps[0]", msg: "pin this action"}]'
assert_failure bash "$root/scripts/normalize-conftest.sh" "$fixtures/normalizers/malformed.json" >/dev/null
assert_failure bash "$root/scripts/normalize-hadolint.sh" "$fixtures/normalizers/malformed.json" >/dev/null
assert_failure bash "$root/scripts/normalize-zizmor.sh" "$fixtures/normalizers/malformed.json" >/dev/null
assert_failure run_aggregate "$missing_exceptions" "$fixtures/empty-findings" kubernetes:skipped \
	| grep -F 'A policy leg unexpectedly skipped: kubernetes'
