# Design notes

Why the policies are written the way they are. Most of these are cases where
the obvious Rego is wrong in a way that fails *open* — the check goes green and
nothing tells you it never really ran.

- [Finding shape](#finding-shape)
- [Kubernetes traversal](#kubernetes-traversal)
- [securityContext inheritance](#securitycontext-inheritance)
- [Image references](#image-references)
- [Allowlists fail closed](#allowlists-fail-closed)
- [GitHub Actions parsing](#github-actions-parsing)
- [Dockerfile scope](#dockerfile-scope)
- [Document guards](#document-guards)
- [Exceptions](#exceptions)

## Finding shape

Every rule emits a structured object rather than a bare string:

```rego
{
  "id": "K8S-002",
  "severity": "high",
  "enforcement": "deny",
  "resource": "Deployment/api",
  "msg": "container \"api\" does not run as non-root",
}
```

Conftest requires the human-readable text under `msg` and surfaces every other
key under `metadata`, which is what `scripts/normalize-conftest.sh` reads to put
Conftest findings in the same shape as Zizmor's and Hadolint's. Container-scoped
findings add `container`; workflow findings add `action` or `runner`.

## Kubernetes traversal

Conftest evaluates one rendered document at a time, and a PodSpec sits at a
different depth per kind. `policy/kubernetes/lib.rego` resolves it once so every
rule is a single `some container in lib.containers`:

| Kind | PodSpec at |
|---|---|
| `Pod` | `spec` |
| `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `Job` | `spec.template.spec` |
| `CronJob` | `spec.jobTemplate.spec.template.spec` |

`lib.containers` walks `initContainers` alongside `containers` — init containers
run with the same privileges as the rest of the pod, so a policy set that only
reads `spec.containers` misses half the attack surface. Names are unique across
both lists, so collapsing them into one set loses nothing.

`pod_spec` is deliberately left undefined for every other kind. That is what
keeps these rules silent on the Services, ConfigMaps, and ServiceAccounts that
come out of the same `helm template` run, instead of each rule re-testing the
kind.

**Traversal is tested on its own.** A traversal gap fails open — a kind that
resolves to no PodSpec yields no containers and therefore no findings, so every
rule test still passes. `lib_test.rego` asserts the reachable container names per
kind rather than relying on the rules to notice.

## securityContext inheritance

Fields inherit pod → container, but a container setting `runAsNonRoot: false`
under a pod that sets `true` must still be denied, because Kubernetes honours the
container. A plain "container value, or else pod value" fallback reads the
explicit `false` as absent and passes exactly the manifest the rule exists to
catch. `lib.inherited_security_context` reads both levels through `object.get`
instead, so an explicit `false` is a value and not a hole.

**Inheritance is per field, not per package.** `runAsNonRoot` (K8S-002) is a
field of both `PodSecurityContext` and the container's `SecurityContext`, so it
inherits. `readOnlyRootFilesystem` (K8S-008) and `capabilities` (K8S-009) exist
only on the container, so a pod-level value is inert — the API drops it and the
kubelet never sees it. Inheriting those two would clear a container the cluster
still runs writable and fully capable, so they read the container alone;
`test_k8s_008_does_not_inherit_from_the_pod` pins that.

K8S-009 tests membership against the literal `"ALL"`, because Kubernetes matches
capability names exactly — a manifest dropping `"all"` drops nothing, and a
case-insensitive check would wave it through.

## Default ServiceAccount (K8S-010)

The default ServiceAccount is shared by everything in the namespace that never
asked for an identity, so its token is the one credential a compromised container
should not be handed — and with nothing to audit, nobody notices it was mounted.

Three spellings reach that same binding: `serviceAccountName` omitted, set to
`"default"`, or set through the deprecated `serviceAccount` alias the API server
still mirrors onto it. Omission is the case that matters most — almost no
manifest names the default SA explicitly, so a rule testing only
`serviceAccountName == "default"` would miss nearly every pod actually bound to
it.

The rule is scoped to an explicit pod-level `automountServiceAccountToken: true`.
Automount resolves from two documents — the pod spec and the ServiceAccount
object, pod winning — and Conftest evaluates one rendered document at a time, so
the ServiceAccount's own setting is out of reach. A pod that says nothing is
therefore left to that setting rather than guessed at; what this rule catches is
a manifest reaching past it to mount the token of an identity nobody scoped.

## Image references

Image references are parsed, not pattern-matched. A registry is only a registry
when the first path component looks like a host (a dot, a port, or `localhost`),
so `nginx:1.27` resolves to `docker.io` rather than to a registry named
`nginx:1.27`, and `myorg/app` to `docker.io` rather than to one named `myorg` —
Docker Hub being exactly what an allowlist needs to catch.

Tags are read from the last path component only, so the port in
`localhost:5000/app` is not mistaken for a tag, and a `@sha256:` digest is
accepted in place of a tag instead of being read as a tag named after its hex.

An image with neither tag nor digest resolves to `latest` at pull time, so
K8S-007 and DOCKER-002 treat it as the same defect in different syntax and give
it the same rule ID.

## Allowlists fail closed

`approved_registries` is built as `{r | some r in data.k8s.approved_registries}`
rather than tested against directly, and the difference is not cosmetic:

```rego
not registry in data.k8s.approved_registries   # passes every image if data never loaded
{r | some r in data.k8s.approved_registries}   # empty set if data never loaded
```

Negative membership against an undefined data path succeeds for everything, so a
run that forgot `--data data/` goes green. Comprehending over the same undefined
reference yields an empty set, so an absent allowlist approves nothing and the
check goes red. K8S-006, DOCKER-001, GHA-002, and GHA-003 all depend on this.

The same shape shows up in `policy/exceptions`: `exc[field]` on a missing key is
undefined, and `not` on an undefined expression is itself undefined rather than
true — so EXC-001 goes through `object.get(exc, field, null)`, or the rule would
silently drop on the exact case it exists to catch.

## GitHub Actions parsing

Workflows key their trigger block `on:`, which YAML 1.1 resolves to the boolean
`true`. The key that actually arrives depends on the parser:

| Key | Producer |
|---|---|
| `"on"` | a YAML 1.2 parser, or a workflow that quotes the key |
| `"true"` | Conftest and `opa test` — the YAML 1.1 boolean survives conversion to JSON, where every object key must be a string |
| `true` | input handed to OPA as native Rego, which allows non-string keys |

`conftest parse` any workflow to see it. Accepting all three is the difference
between a policy that runs and one that silently matches nothing; the failure
mode is a green check, so it is worth the three lines.

`action_refs` collects `jobs.<id>.steps[].uses` and `jobs.<id>.uses` into one
set — reusable-workflow calls are action references under the same supply-chain
argument. Actions under `./` are in the caller's own repository, reviewed with
it, so they carry no third-party risk and no ref to pin.

GHA-003 checks each runner label rather than the whole `runs-on` value, which
stops a self-hosted runner from riding along as an extra label next to an
approved one. `runs-on` is a string, a list, or `{group, labels}`, so
`runner_labels` handles all three.

GHA-001 overlaps with [Zizmor](https://docs.zizmor.sh/) by design. It is written
in Rego to show the parsing above. Zizmor owns the deeper analysis — template
injection, excessive permissions, artifact poisoning — and this package does not
attempt any of it.

## Dockerfile scope

[Hadolint](https://github.com/hadolint/hadolint) owns every instruction except
`FROM`. Keeping that boundary explicit avoids two tools issuing different
verdicts on the same hygiene rule.

Stage aliases are local references, not images, so `stage_aliases` is resolved
before checking `FROM` values — otherwise `FROM builder` in a multi-stage build
reads as an untagged Docker Hub image.

## Document guards

Conftest hands a package every document it was pointed at, so each package
identifies its own input rather than trusting the caller:

| Package | Guard |
|---|---|
| `kubernetes` | `lib.pod_spec` is undefined for non-workload kinds |
| `github` | a trigger block plus an object `jobs` |
| `helm` | root-level `apiVersion` in `{v1, v2}` and a string `name` |
| `dockerfile` | an array containing a `from` instruction with a numeric stage |
| `repo` | `input.files` is an array |

The `repo` guard is the one that has to be repeated per rule: `not has_license`
succeeds for every document that lacks `files`, so without the guard every
workflow and rendered manifest Conftest sees would be reported as a missing
LICENSE.

## Exceptions

Input is a consumer's `.platform-policy-exceptions.yaml`:

```yaml
exceptions:
  - id: K8S-006
    resource: Deployment/legacy-app   # optional; absent suppresses every K8S-006
    owner: platform-team
    ticket: JIRA-123
    reason: registry migration in progress
    expires: 2026-12-31
```

`resource` is optional and, when absent, suppresses every finding for that rule
ID rather than one — a broader grant, which is why `owner`, `ticket`, `reason`,
and `expires` are mandatory on every entry regardless of scope. A missing field
is what makes an exception impossible to audit later, so it is rejected the same
way an expired one is.

**A wildcard `id` is rejected (EXC-002)** because an exception is a documented,
reviewed carve-out for one violation; a wildcard turns it into a blanket
suppression no reviewer signed off on.

**An unparseable `expires` is rejected (EXC-003)** rather than silently treated
as never-expiring — a format Rego cannot parse cannot be checked for expiry.

**An expired entry fails closed (EXC-004).** Once that `deny` reaches the
aggregated summary it blocks the run, the same as if the exception did not
exist, rather than quietly ceasing to suppress while everything else stays green.

**An exception may last no more than 90 days (EXC-005).** This keeps the
break-glass mechanism temporary; a longer waiver must be renewed explicitly.

`policy/exceptions` validates shape and expiry and is the only thing that decides
which entries are usable; `scripts/apply-exceptions.sh` consumes
`data.exceptions.active` and never re-derives that judgment, so an entry that
fails closed in the Rego cannot still suppress a finding in the shell.

`active` is derived by subtracting `deny` rather than by restating its
conditions:

```rego
rejected := {m.resource | some m in deny}
```

A new `EXC-*` rule therefore disqualifies its entry the moment it is written,
where a second copy of the conditions would fail open every time someone added a
rule and forgot to update it.

Exceptions never apply to the `EXC-*` findings themselves — otherwise an
exceptions file could suppress the validation that would have failed it closed.
