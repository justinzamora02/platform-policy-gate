# platform-policy-gate

Tested OPA/Rego policies delivered as a reusable GitHub Actions workflow — gates rendered Helm output, Dockerfiles, and CI workflows.

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

All three accept `OPA=` / `CONFTEST=` overrides if your binaries live elsewhere.

### Rule coverage

`scripts/rule-coverage.sh` fails the build when a policy can emit a rule ID that
no test ever trips. Grepping the IDs out of `policy/` and out of
`policy/*_test.rego` would report full coverage forever — the ID an assertion
names is the same string the rule defines, and a comment mentioning a rule reads
the same as the rule. So the two sides come from two tools instead: `opa parse
--json-include locations` for the IDs a policy can emit (an AST has no comments
in it), and `opa test --coverage` for the ones a test actually reached. A deny
body's `msg := ...` is only covered when the rule fired, which is the distinction
the gate turns on.

The unit is the emission site, not the ID — K8S-007 denies `:latest` and an
untagged image from two separate rule bodies, and each needs its own test. Both
sides are discovered at run time, so a new package is under the gate as soon as
it is committed.

### Self-enforcement

`scripts/self-check.sh` runs the published rules against this repository. The
tests prove a rule fires correctly against a fixture; they say nothing about
whether the repo shipping the rule obeys it. Without this, `uses:
actions/checkout@v5` could land in `.github/workflows/` here, every fixture
would still pass, and a repository whose whole argument is policy-as-code would
merge an unpinned action behind a green check.

It evaluates two namespaces, because the two packages read two different kinds
of document: `github` over `.github/workflows/`, and `repo` over an inventory
generated from the working tree by `scripts/repo-inventory.sh`. Both run before
the script exits, so one run reports everything wrong rather than the first
thing. The inventory goes to a temp directory — it is an artifact of the current
tree, not a source file, and `make inventory` remains the way to write one out
for inspection (`repo-inventory.json`, gitignored).

It is part of `make check`, and also a step of its own in CI, ahead of `make
check`. The duplicated run costs under a second and buys a distinction worth
seeing in the job summary: `make check` red means the policies are broken, and
self-check red means the policies are fine and *this repository* violates them.

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
    uses: justinzamora02/platform-policy-gate/.github/workflows/policy-check.yml@v1
    with:
      manifest-paths: manifests
      policy-ref: v1
```

| Input | Required | Default | Purpose |
|---|---|---|---|
| `manifest-paths` | no | `manifests` | Whitespace-separated files or directories to scan, walked recursively. No glob expansion, and no paths containing spaces. |
| `policy-ref` | **yes** | — | Ref of this repository to evaluate against. No default, so a rule added here can never change a caller's verdict without a commit. |
| `policy-repository` | no | `justinzamora02/platform-policy-gate` | Override to test policy changes from a fork. |
| `fail-on-warn` | no | `false` | Also fail on `warn` findings, for rules still inside their grace period. |
| `exceptions-file` | no | `.platform-policy-exceptions.yaml` | Path to a policy-exceptions file. Absent suppresses nothing and is not an error; present-but-invalid fails closed as `deny`. |

Helm charts are discovered by `Chart.yaml` anywhere in the caller's repository.
Each chart is linted and rendered once for every chart-local `values*.yaml`
file; a chart with none is rendered once with its defaults. The matrix check
name includes the exact values path, or says that chart defaults were used, so
a passing check cannot imply coverage beyond the committed values. A dedicated
check reports `no charts found` when discovery is empty.

### Exceptions

An entry in the exceptions file suppresses matching findings until it expires:

```yaml
exceptions:
  - id: K8S-006
    resource: Deployment/legacy-app   # optional; absent suppresses every K8S-006
    owner: platform-team
    ticket: JIRA-123
    reason: registry migration in progress
    expires: 2026-12-31
```

`policy/exceptions` validates shape and expiry, and is the only thing that
decides which entries are usable — `scripts/apply-exceptions.sh` never
re-derives that, so an entry that fails closed there cannot still suppress a
finding. A missing field, a wildcard `id`, an unparseable date, or a past
`expires` each disqualify the entry *and* emit their own `deny`, so a lapsed
exception blocks the run rather than quietly ceasing to suppress. Exceptions
never apply to the `EXC-*` findings themselves.

## Layout

```
policy/<package>/*.rego          policies, one package per domain
policy/<package>/*_test.rego     unit tests, colocated
test/fixtures/<package>/<case>/  fixture documents
data/<package>.yaml              config and allowlists a package reads from
scripts/                         helpers used by make and by the workflow
```

Fixtures are loaded by directory, not by filename: `opa test policy/ test/ data/`
puts `test/fixtures/repo/license-missing/inventory.yaml` at
`data.fixtures.repo["license-missing"]`. Files directly under a load root merge
at the top, so `data/gha.yaml` lands on `data.gha` — one config document per
policy package, keyed separately from the policy namespace it configures.

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

**Dockerfile** (`policy/dockerfile`) — evaluated against parsed Dockerfiles:

| ID | Rule |
|---|---|
| DOCKER-001 | Base images come from registries in `data/docker.yaml` |
| DOCKER-002 | Base images do not use `:latest` or an untagged reference |

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

Every rule emits a structured object — `msg` for the human text (Conftest
requires it under that key), plus `id`, `severity`, `enforcement`, and
`resource`, which Conftest surfaces under `metadata` for the aggregation step.
Container-scoped findings add `container`; workflow findings add `action` or
`runner`.

Conftest defaults to the `main` namespace, so evaluating a package directly
means naming it:

```sh
conftest test --policy policy --data data/ --namespace kubernetes rendered.yaml
```

K8S-006, DOCKER-001, GHA-002, and GHA-003 read their allowlists from `data/`,
so widening one is a review of a YAML file, not a change to Rego:

```sh
conftest test --policy policy --namespace github --data data/ \
  .github/workflows/test.yml
```

GHA-001 overlaps with [Zizmor](https://docs.zizmor.sh/) by design. It is
written in Rego to show the parsing — notably that `on:` is a YAML 1.1 boolean,
so the trigger key reaches a policy as `"on"`, `"true"`, or `true` depending on
the parser (`conftest parse` any workflow to see it). Zizmor owns the deeper
analysis: template injection, excessive permissions, artifact poisoning. This
package does not attempt any of that.

`--data data/` is not optional. K8S-006, DOCKER-001, and GHA-002 fail closed
without it — an allowlist that never loaded approves nothing, so the check goes
red rather than silently green. See the note on `approved_registries` under
Kubernetes below for how that is arranged, and why it does not come for free.

Repo-hygiene rules evaluate a repository inventory rather than a manifest:

```sh
make inventory   # writes repo-inventory.json
conftest test --policy policy --namespace repo repo-inventory.json
```

### Kubernetes traversal

A PodSpec sits at a different depth per kind, so `policy/kubernetes/lib.rego`
resolves it once and every rule reads `lib.containers`:

| Kind | PodSpec at |
|---|---|
| `Pod` | `spec` |
| `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `Job` | `spec.template.spec` |
| `CronJob` | `spec.jobTemplate.spec.template.spec` |

It walks `initContainers` alongside `containers` — init containers run with the
same privileges as the rest of the pod, so a policy set that only reads
`spec.containers` misses half the attack surface. `pod_spec` is left undefined
for every other kind, which is what keeps the rules silent on the Services and
ConfigMaps that come out of the same `helm template` run.

Five things this package is deliberate about:

- **`securityContext` inheritance.** Fields inherit pod → container, but a
  container setting `runAsNonRoot: false` under a pod that sets `true` must
  still be denied, because Kubernetes honours the container. A plain
  "container value, or else pod value" fallback reads the explicit `false` as
  absent and passes exactly the manifest the rule exists to catch, so both
  levels are read through `object.get` instead.
- **Image references are parsed, not pattern-matched.** A registry is only a
  registry when the first path component looks like a host (a dot, a port, or
  `localhost`), so `nginx:1.27` resolves to `docker.io` rather than to a
  registry named `nginx:1.27`, and `myorg/app` to `docker.io` rather than to
  one named `myorg` — Docker Hub being exactly what an allowlist needs to
  catch. Tags are read from the last path component only, so the port in
  `localhost:5000/app` is not mistaken for a tag, and a `@sha256:` digest is
  accepted in place of one instead of being read as a tag named after its hex.
- **The allowlist is read through a comprehension.** `approved_registries` is
  built as `{r | some r in data.k8s.approved_registries}` rather than tested
  against directly, and the difference is not cosmetic: `not registry in
  data.k8s.approved_registries` *passes every image* when that data was never
  loaded, so a run that forgot `--data data/` goes green. Comprehending over
  the same undefined reference yields an empty set, so an absent allowlist
  approves nothing and the check fails closed.
- **Inheritance is per field, not per package.** `runAsNonRoot` (K8S-002) is a
  field of both `PodSecurityContext` and the container's `SecurityContext`, so
  it inherits. `readOnlyRootFilesystem` (K8S-008) and `capabilities` (K8S-009)
  exist only on the container, so a pod-level value is inert — the API drops it
  and the kubelet never sees it. Inheriting those two would clear a container
  the cluster still runs writable and fully capable, so they read the container
  alone; `test_k8s_008_does_not_inherit_from_the_pod` pins that.
- **Traversal is tested on its own.** A traversal gap fails *open* — a kind
  that resolves to no PodSpec yields no containers and therefore no findings,
  so every rule test still passes. `lib_test.rego` asserts the reachable
  container names per kind rather than relying on the rules to notice.

## Production gap

What this demo does not do, and what would change with real infrastructure
behind it. Knowing the limits of your own system is worth more than pretending
they don't exist.

- **CI is not an enforcement boundary.** Anything not applied through this
  pipeline is unchecked. In production the authoritative control is an
  admission controller (Kyverno or Gatekeeper); this pipeline would become
  fast feedback in front of it, and the k8s policies would be authored for the
  admission layer and run in CI from the same source to avoid drift.
- **Values coverage is partial.** Charts are rendered against the
  `values*.yaml` files committed in the repo. Real deployment values often
  live in a GitOps repo or ArgoCD `Application`, so a green check proves the
  committed values are compliant — nothing more. The output states which
  values files were evaluated.
- **Adoption is voluntary here.** In an org, the check would be required via
  an organization ruleset, and new rules would need a `warn → deny` lifecycle
  with lead time so a policy change doesn't break every repo on merge day.
- **Findings are surfaced as job summaries, not SARIF.** SARIF upload to code
  scanning would be the production choice; Conftest has no native SARIF
  output, so it requires a converter.
