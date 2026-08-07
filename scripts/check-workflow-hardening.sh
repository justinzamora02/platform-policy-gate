#!/usr/bin/env bash
# Assert fail-closed controls that policy rules cannot express.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

workflow=.github/workflows/policy-check.yml

assert() {
	if ! conftest parse "$workflow" | jq -e "$1" >/dev/null; then
		echo "workflow hardening: $2" >&2
		exit 1
	fi
}

assert_installer() {
	local file=$1 name=$2 variable=$3 checksum=$4 archive=$5 install=$6 count=$7
	if ! conftest parse "$file" | jq -e \
		--arg name "$name" --arg variable "$variable" --arg checksum "$checksum" \
		--arg archive "$archive" --arg install "$install" --argjson count "$count" '
		[.jobs[] | .steps[]? | select(.name == $name)] as $steps
		| ($steps | length) == $count
		  and all($steps[];
			.env[$variable] == $checksum
			and (.run | contains("-o \"$RUNNER_TEMP/" + $archive + "\""))
			and (.run | contains("echo \"${" + $variable + "}  $RUNNER_TEMP/" + $archive + "\" | sha256sum -c -"))
			and (.run | contains($install)))
	' >/dev/null; then
		echo "workflow hardening: $file $name installer is not checksum-bound" >&2
		exit 1
	fi
}

assert '(.true.workflow_call.inputs | has("policy-ref") | not) and (.true.workflow_call.inputs | has("policy-repository") | not)' 'caller controls the policy source'
assert '[.jobs[] | .steps[]? | select(.name == "Check out the policies") | .with] as $checkouts | ($checkouts | length) == 10 and all($checkouts[]; .repository == "${{ job.workflow_repository }}" and .ref == "${{ job.workflow_sha }}")' 'a policy checkout is not bound to the workflow source'
assert '(.jobs.kubernetes.steps[] | select(.name == "Conftest — Kubernetes manifests") | .run | contains("if [ \"${#paths[@]}\" -eq 0 ]; then") and contains("case \"$path\" in") and contains("-- \"${paths[@]}\" >raw.json"))' 'manifest paths are not fail-closed'
assert '(.jobs.aggregate.needs | index("discover-helm")) and (.jobs.aggregate.steps[] | select(.name == "Fail if a policy leg did not complete") | .run | contains("if [ \"$DISCOVER_HELM_STATUS\" != \"success\" ]; then") and contains("\"success skipped\"|\"skipped success\") ;;"))' 'Helm dependency failures are not fail-closed'
assert '(.jobs.helm.steps[] | select(.name == "Conftest — rendered Helm chart") | .run | contains("helm template policy-check \"${helm_args[@]}\" >rendered.yaml") and contains("case \"$conftest_status\" in") and contains("0|1) ;;") and contains("jq -e '\''type == \"array\"'\'' raw.json >/dev/null"))' 'Helm rendering does not distinguish tool failure from findings'

conftest_sha=e8144c6d6d2ae0260b869caa60c7c262a1f95ac63ec1e5d2fb19be452d606347
zizmor_sha=e87b67160194884e375a46a12c57ccc904f762b53845f254fab7f17d98809c09
hadolint_sha=56de6d5e5ec427e17b74fa48d51271c7fc0d61244bf5c90e828aab8362d55010

assert_installer "$workflow" 'Install conftest' CONFTEST_SHA256 "$conftest_sha" conftest.tar.gz 'sudo tar -xzf "$RUNNER_TEMP/conftest.tar.gz" -C /usr/local/bin conftest' 7
assert_installer "$workflow" 'Install Zizmor' ZIZMOR_SHA256 "$zizmor_sha" zizmor.tar.gz 'sudo tar -xzf "$RUNNER_TEMP/zizmor.tar.gz" -C /usr/local/bin zizmor' 1
assert_installer "$workflow" 'Install Hadolint' HADOLINT_SHA256 "$hadolint_sha" hadolint 'sudo install -m 0755 "$RUNNER_TEMP/hadolint" /usr/local/bin/hadolint' 1
assert_installer .github/workflows/test.yml 'Install conftest' CONFTEST_SHA256 "$conftest_sha" conftest.tar.gz 'sudo tar -xzf "$RUNNER_TEMP/conftest.tar.gz" -C /usr/local/bin conftest' 1
assert_installer .github/workflows/release.yml 'Install conftest' CONFTEST_SHA256 "$conftest_sha" conftest.tar.gz 'sudo tar -xzf "$RUNNER_TEMP/conftest.tar.gz" -C /usr/local/bin conftest' 1
