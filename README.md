# platform-policy-gate

Tested OPA/Rego policies delivered as a reusable GitHub Actions workflow — gates
rendered Helm output, Dockerfiles, and CI workflows.

- [docs/design.md](docs/design.md) — why the policies are written the way they are
- [docs/testing.md](docs/testing.md) — rule coverage and self-enforcement
- [docs/production-gap.md](docs/production-gap.md) — what this demo does not do
- [contribution.md](contribution.md) — how to contribute

### Local commit gate

Enable the versioned Git hook once per clone:

```sh
./setup.sh
```

This configures `core.hooksPath`, verifies the required tools, and runs the
first check. The `pre-commit` hook then runs `make check` and blocks commits
when the check fails. CI remains the authoritative gate for commits made
without the local hook; configure GitHub branch protection to require the
`test / policy-tests` check on `master`.

## Using it from another repository

`.github/workflows/policy-check.yml` is a reusable workflow. It checks out the
caller, checks out the policy source at the reusable workflow's pinned commit, and evaluates the
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
```

| Input | Required | Default | Purpose |
|---|---|---|---|
| `manifest-paths` | no | `manifests` | Whitespace-separated files or directories to scan, walked recursively. No glob expansion, and no paths containing spaces. |
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

A missing field, a wildcard `id`, an unparseable date, a past `expires`, or an
expiry more than 90 days out each disqualify the entry *and* emit their own
`deny`, so exceptions remain short-lived and a lapsed exception blocks the run.
See
[docs/design.md § Exceptions](docs/design.md#exceptions).

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
| K8S-010 | Default ServiceAccounts explicitly set `automountServiceAccountToken: false` |
| K8S-016 | Roles do not use wildcard API groups, resources, or verbs |
| K8S-017 | Roles do not grant `escalate`, `bind`, or `impersonate` |
| K8S-018 | ClusterRoles do not grant read access to core `secrets` |
| K8S-019 | No binding grants the built-in `cluster-admin` role |
| K8S-013 | `capabilities.add` limited to the `allowed_capabilities` list in `data/k8s.yaml` |
| K8S-014 | No `hostPort` on any container |

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

**Node.js** (`policy/node`) — root `package.json` projects only:

| ID | Rule |
|---|---|
| NODE-001 | `packageManager` declares an exact pnpm version |
| NODE-002 | `engines.node` selects an approved Node.js LTS line (`data/node.yaml`) |
| NODE-003 | `pnpm-lock.yaml` is present at the repository root |
| NODE-004 | Competing npm, Yarn, or Bun lockfiles are absent |

Node policy intentionally accepts only canonical single-major constraints; it
does not implement npm's full semver-range grammar. The approved LTS list must
be updated deliberately as Node release lines change.

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
| EXC-005 | `expires` is no more than 90 days out |

Every rule emits a structured object rather than a bare string — see
[docs/design.md § Finding shape](docs/design.md#finding-shape).
