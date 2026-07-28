# platform-policy-gate

Tested OPA/Rego policies delivered as a reusable GitHub Actions workflow — gates rendered Helm output, Dockerfiles, and CI workflows.

## Quickstart

Needs [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa) and
[`conftest`](https://www.conftest.dev/install/) on `PATH`
(`brew install opa conftest`).

```sh
make test    # opa test + conftest verify
make check   # formatting + strict type check + tests (what CI runs)
```

Both accept `OPA=` / `CONFTEST=` overrides if your binaries live elsewhere.

## Layout

```
policy/<package>/*.rego          policies, one package per domain
policy/<package>/*_test.rego     unit tests, colocated
test/fixtures/<package>/<case>/  fixture documents
data/                            allowlists the policies read from
scripts/                         helpers used by make and by the workflow
```

Fixtures are loaded by directory, not by filename: `opa test policy/ test/`
puts `test/fixtures/repo/license-missing/inventory.yaml` at
`data.fixtures.repo["license-missing"]`.

## Rules

| ID | Rule |
|---|---|
| REPO-001 | LICENSE file present at the repository root |

Every rule emits a structured object — `msg` for the human text (Conftest
requires it under that key), plus `id`, `severity`, `enforcement`, and
`resource`, which Conftest surfaces under `metadata` for the aggregation step.

Repo-hygiene rules evaluate a repository inventory rather than a manifest:

```sh
make inventory   # writes repo-inventory.json
conftest test --policy policy/repo --namespace repo repo-inventory.json
```
