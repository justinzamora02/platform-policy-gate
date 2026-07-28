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

**Kubernetes** (`policy/kubernetes`) — evaluated against rendered manifests:

| ID | Rule |
|---|---|
| K8S-001 | No privileged containers |
| K8S-002 | Containers must run as non-root |
| K8S-003 | No `hostNetwork`, `hostPID`, or `hostIPC` |
| K8S-004 | No `hostPath` volumes |

**Repo hygiene** (`policy/repo`):

| ID | Rule |
|---|---|
| REPO-001 | LICENSE file present at the repository root |

Every rule emits a structured object — `msg` for the human text (Conftest
requires it under that key), plus `id`, `severity`, `enforcement`, and
`resource`, which Conftest surfaces under `metadata` for the aggregation step.
Container-scoped findings add `container`.

Conftest defaults to the `main` namespace, so evaluating a package directly
means naming it:

```sh
conftest test --policy policy --namespace kubernetes rendered.yaml
```

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
