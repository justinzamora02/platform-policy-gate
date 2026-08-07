#!/usr/bin/env bash
# Validate policy-leg completion and artifacts, then suppress and aggregate.
#
# Usage: aggregate-policy-check.sh <exceptions-file> <findings-dir> <job:status>...
set -euo pipefail

if [[ $# -lt 3 ]]; then
	echo "usage: aggregate-policy-check.sh <exceptions-file> <findings-dir> <job:status>..." >&2
	exit 2
fi

exceptions_file="$1"
findings_dir="$2"
shift 2
shopt -s nullglob
discover_helm_status=""
helm_status=""
no_helm_charts_status=""

for job_status in "$@"; do
	job="${job_status%%:*}"
	status="${job_status#*:}"
	if [[ "$job" = "$job_status" ]]; then
		echo "invalid job status: $job_status" >&2
		exit 2
	fi
	case "$job" in
		discover-helm) discover_helm_status="$status" ;;
		helm) helm_status="$status" ;;
		no-helm-charts) no_helm_charts_status="$status" ;;
	esac

	case "$status" in
		success) ;;
		skipped)
			case "$job" in
				helm|no-helm-charts|hadolint|dockerfile) ;;
				*)
					echo "::error::A policy leg unexpectedly skipped: $job" >&2
					exit 1
					;;
			esac
			;;
		*)
			echo "::error::A policy leg ended with status: $status" >&2
			exit 1
			;;
	esac

	case "$job" in
		kubernetes) artifact="findings-kubernetes" ;;
		helm) artifact="findings-helm-*" ;;
		zizmor) artifact="findings-zizmor" ;;
		hadolint) artifact="findings-hadolint" ;;
		dockerfile) artifact="findings-dockerfile" ;;
		github-workflows) artifact="findings-github-workflows" ;;
		repo-hygiene) artifact="findings-repo-hygiene" ;;
		node) artifact="findings-node" ;;
		exceptions) artifact="findings-exceptions" ;;
		*) continue ;;
	esac

	if [[ "$status" = "success" ]]; then
		artifacts=("$findings_dir"/$artifact/findings.json)
		if [[ ${#artifacts[@]} -eq 0 ]]; then
			echo "missing or empty findings artifact: $artifact" >&2
			exit 1
		fi
		for artifact_file in "${artifacts[@]}"; do
			if [[ ! -s "$artifact_file" ]]; then
				echo "missing or empty findings artifact: $artifact" >&2
				exit 1
			fi
	done
	fi
done

if [[ "$discover_helm_status" != "success" ]]; then
	echo "Helm discovery did not succeed: ${discover_helm_status:-missing}" >&2
	exit 1
fi

if ! { [[ "$helm_status" = "success" && "$no_helm_charts_status" = "skipped" ]] || [[ "$helm_status" = "skipped" && "$no_helm_charts_status" = "success" ]]; }; then
	echo "exactly one Helm result must be success (helm=$helm_status, no-helm-charts=$no_helm_charts_status)" >&2
	exit 1
fi

source_files=("$findings_dir"/*/findings.json)
if [[ ${#source_files[@]} -eq 0 ]]; then
	echo "missing or empty findings artifact" >&2
	exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
findings_files=()

for source in "${source_files[@]}"; do
	if ! jq -e 'type == "array"' "$source" >/dev/null; then
		echo "invalid normalized findings: $source" >&2
		exit 1
	fi

	name="$(basename "$(dirname "$source")")"
	target="$work/$name.json"
	if [[ "$name" = "findings-exceptions" ]]; then
		cp "$source" "$target"
	else
		"$(dirname "${BASH_SOURCE[0]}")/apply-exceptions.sh" "$exceptions_file" "$source" >"$target"
	fi
	findings_files+=("$target")
done

"$(dirname "${BASH_SOURCE[0]}")/aggregate-findings.sh" "${findings_files[@]}"
