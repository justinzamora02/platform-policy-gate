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
conftest test --policy policy --data data/ --namespace kubernetes rendered.yaml
```

K8S-006, GHA-002, and GHA-003 read their allowlists from `data/`, so widening one is a
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

`--data data/` is not optional. K8S-006 and GHA-002 fail closed without it — an
allowlist that never loaded approves nothing, so the check goes red rather than
silently green. See the note on `approved_registries` under Kubernetes below for
how that is arranged, and why it does not come for free.

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
