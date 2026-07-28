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
data/<package>.yaml              config and allowlists a package reads from
scripts/                         helpers used by make and by the workflow
```

Fixtures are loaded by directory, not by filename: `opa test policy/ test/ data/`
puts `test/fixtures/repo/license-missing/inventory.yaml` at
`data.fixtures.repo["license-missing"]`. Files directly under a load root merge
at the top, so `data/gha.yaml` lands on `data.gha` — one config document per policy
package, keyed by the package it configures.

## Rules

**Kubernetes** (`policy/kubernetes`) — evaluated against rendered manifests:

| ID | Rule |
|---|---|
| K8S-001 | No privileged containers |
| K8S-002 | Containers must run as non-root |
| K8S-003 | No `hostNetwork`, `hostPID`, or `hostIPC` |
| K8S-004 | No `hostPath` volumes |

**GitHub Actions** (`policy/github`) — evaluated against workflow files:

| ID | Rule |
|---|---|
| GHA-001 | Third-party actions pinned to a full commit SHA |
| GHA-002 | Actions appear in the `approved_actions` list in `data/gha.yaml` |
| GHA-003 | Runner labels appear in the `approved_runners` list in `data/gha.yaml` |

**Repo hygiene** (`policy/repo`):

| ID | Rule |
|---|---|
| REPO-001 | LICENSE file present at the repository root |

Every rule emits a structured object — `msg` for the human text (Conftest
requires it under that key), plus `id`, `severity`, `enforcement`, and
`resource`, which Conftest surfaces under `metadata` for the aggregation step.
Container-scoped findings add `container`; workflow findings add `action` or
`runner`.

Conftest defaults to the `main` namespace, so evaluating a package directly
means naming it:

```sh
conftest test --policy policy --namespace kubernetes rendered.yaml
```

GHA-002 and GHA-003 read their allowlists from `data/`, so widening one is a
review of a YAML file, not a change to Rego:

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

Two things this package is deliberate about:

- **`securityContext` inheritance.** Fields inherit pod → container, but a
  container setting `runAsNonRoot: false` under a pod that sets `true` must
  still be denied, because Kubernetes honours the container. A plain
  "container value, or else pod value" fallback reads the explicit `false` as
  absent and passes exactly the manifest the rule exists to catch, so both
  levels are read through `object.get` instead.
- **Traversal is tested on its own.** A traversal gap fails *open* — a kind
  that resolves to no PodSpec yields no containers and therefore no findings,
  so every rule test still passes. `lib_test.rego` asserts the reachable
  container names per kind rather than relying on the rules to notice.
