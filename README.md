# platform-policy-gate

Tested OPA/Rego policies delivered as a reusable GitHub Actions workflow — gates
rendered Helm output, Dockerfiles, and CI workflows.

- [docs/design.md](docs/design.md) — why the policies are written the way they are
- [docs/testing.md](docs/testing.md) — rule coverage and self-enforcement
- [docs/production-gap.md](docs/production-gap.md) — what this demo does not do

## Quickstart

Needs [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa) and
[`conftest`](https://www.conftest.dev/install/) on `PATH`
(`brew install opa conftest`).

```sh
make test        # opa test + conftest verify
make coverage    # fail if any rule has no test that trips it
make self-check  # evaluate this repo's own workflows and inventory against these rules
make check       # all of the above, plus formatting and a strict type check (what CI runs)
```

All of them accept `OPA=` / `CONFTEST=` overrides if your binaries live
elsewhere. The gates behind `coverage` and `self-check` are described in
[docs/testing.md](docs/testing.md).

## Using it from another repository

`.github/workflows/policy-check.yml` is a reusable workflow. It checks out the
caller, checks out this repository at the ref the caller pins, and evaluates the
caller's Kubernetes manifests and locally rendered Helm charts (Conftest),
workflows (Conftest + [Zizmor](https://docs.zizmor.sh/)), and Dockerfiles
(Conftest + [Hadolint](https://github.com/hadolint/hadolint)).

Every leg writes its findings as an artifact and gates on nothing. A final
`aggregate` job merges them into one job summary and is the only job that fails
the run — one red/green signal instead of four tools' output to open
individually. Any `deny` fails it.

```yaml
jobs:
  policy:
    uses: justinzamora02/platform-policy-gate/.github/workflows/policy-check.yml@c215e7e59ff45a3143b7e42e955c3c10046ef9a5 # master — no v1 tag published yet
    with:
      manifest-paths: manifests
      policy-ref: c215e7e59ff45a3143b7e42e955c3c10046ef9a5 # master — no v1 tag published yet
```

| Input | Required | Default | Purpose |
|---|---|---|---|
| `manifest-paths` | no | `manifests` | Whitespace-separated files or directories to scan, walked recursively. No glob expansion, and no paths containing spaces. |
| `policy-ref` | **yes** | — | Ref of this repository to evaluate against. No default, so a rule added here can never change a caller's verdict without a commit. |
| `policy-repository` | no | `justinzamora02/platform-policy-gate` | Override to test policy changes from a fork. |
| `fail-on-warn` | no | `false` | Also fail on `warn` findings, for rules still inside their grace period. |
| `exceptions-file` | no | `.platform-policy-exceptions.yaml` | Path to a policy-exceptions file. Absent suppresses nothing and is not an error; present-but-invalid fails closed as `deny`. |

Helm charts are discovered by `Chart.yaml` anywhere in the caller's repository.
Each chart is linted and rendered once for every chart-local `values*.yaml` file;
a chart with none is rendered once with its defaults. The matrix check name
includes the exact values path, or says that chart defaults were used, so a
passing check cannot imply coverage beyond the committed values. A dedicated
check reports `no charts found` when discovery is empty.

### Exceptions

An entry in `.platform-policy-exceptions.yaml` suppresses matching findings until
it expires:

```yaml
exceptions:
  - id: K8S-006
    resource: Deployment/legacy-app   # optional; absent suppresses every K8S-006
    owner: platform-team
    ticket: JIRA-123
    reason: registry migration in progress
    expires: 2026-12-31
```

A missing field, a wildcard `id`, an unparseable date, or a past `expires` each
disqualify the entry *and* emit their own `deny`, so a lapsed exception blocks
the run rather than quietly ceasing to suppress. See
[docs/design.md § Exceptions](docs/design.md#exceptions).

## Releasing

`.github/workflows/release.yml` is triggered by hand — Actions → release → Run
workflow, from `master`, with a version like `v1.2.0`. It re-runs `make
self-check` and `make check` on the selected commit, then creates the tag and
the GitHub release in one `gh release create`.

There is no floating `v1` alias, and the workflow refuses a version whose tag
already exists. A tag is the unit of distribution: consumers pin `policy-ref`
to one, and the argument for `policy-ref` having no default — a rule added here
must not change a caller's verdict without a commit on the caller's side —
holds only while the tag they pinned stays on the commit that was reviewed.
Upgrading is therefore an explicit bump of both refs in the caller's workflow.

Releases are cut from `master` only. Both that and the version format are shell
checks rather than a job-level `if`, because a skipped job reports green, and a
release workflow that can report green without releasing anything is worse than
one that fails.

## Layout

```
policy/<package>/*.rego          policies, one package per domain
policy/<package>/*_test.rego     unit tests, colocated
test/fixtures/<package>/<case>/  fixture documents
data/<package>.yaml              config and allowlists a package reads from
scripts/                         helpers used by make and by the workflow
docs/                            design notes
```

## Rules

**Kubernetes** (`policy/kubernetes`) — evaluated against rendered manifests:

| ID | Rule |
|---|---|
| K8S-001 | No privileged containers |
| K8S-002 | Containers must run as non-root |
| K8S-003 | No `hostNetwork`, `hostPID`, or `hostIPC` |
| K8S-004 | No `hostPath` volumes |
| K8S-005 | CPU and memory requests and limits required |
| K8S-006 | Images from registries in `data/k8s.yaml` |
| K8S-007 | No `:latest` and no untagged images |
| K8S-008 | `readOnlyRootFilesystem: true` on every container |
| K8S-009 | `capabilities.drop` must include `ALL` |
| K8S-010 | No `automountServiceAccountToken: true` on the default ServiceAccount |

**GitHub Actions** (`policy/github`) — evaluated against workflow files:

| ID | Rule |
|---|---|
| GHA-001 | Third-party actions pinned to a full commit SHA |
| GHA-002 | Actions appear in the `approved_actions` list in `data/gha.yaml` |
| GHA-003 | Runner labels appear in the `approved_runners` list in `data/gha.yaml` |
| GHA-004 | Workflows declare an explicit `permissions` block and do not use `write-all` |

**Dockerfile** (`policy/dockerfile`) — evaluated against parsed Dockerfiles:

| ID | Rule |
|---|---|
| DOCKER-001 | Base images come from registries in `data/docker.yaml` |
| DOCKER-002 | Base images do not use `:latest` or an untagged reference |
| DOCKER-003 | The final image stage declares a non-root `USER` |

**Helm** (`policy/helm`) — evaluated against `Chart.yaml`:

| ID | Rule |
|---|---|
| HELM-001 | At least one maintainer declared |
| HELM-002 | Description declared |
| HELM-003 | Version is valid semantic versioning |

**Repo hygiene** (`policy/repo`):

| ID | Rule |
|---|---|
| REPO-001 | LICENSE file present at the repository root |
| REPO-002 | CODEOWNERS file present at the root, `.github/`, or `docs/` |

**Exceptions** (`policy/exceptions`) — evaluated against the exceptions file:

| ID | Rule |
|---|---|
| EXC-001 | `id`, `owner`, `ticket`, `reason`, and `expires` all present |
| EXC-002 | `id` names one rule, not a wildcard |
| EXC-003 | `expires` is a `YYYY-MM-DD` date |
| EXC-004 | `expires` is in the future |

Every rule emits a structured object rather than a bare string — see
[docs/design.md § Finding shape](docs/design.md#finding-shape).

### Running a package directly

Conftest defaults to the `main` namespace, so evaluating a package means naming
it. `--data data/` is not optional either: K8S-006, DOCKER-001, GHA-002, and
GHA-003 read their allowlists from `data/` and
[fail closed](docs/design.md#allowlists-fail-closed) without it.

```sh
conftest test --policy policy --data data/ --namespace kubernetes rendered.yaml
conftest test --policy policy --data data/ --namespace github .github/workflows/test.yml
```

Widening an allowlist is therefore a review of a YAML file, not a change to Rego.

Repo-hygiene rules evaluate a repository inventory rather than a manifest:

```sh
make inventory   # writes repo-inventory.json
conftest test --policy policy --namespace repo repo-inventory.json
```
