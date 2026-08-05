# AGENTS.md

Conventions for agents working in this repository. Read
[docs/design.md](docs/design.md) before changing a policy — most of the rules
here exist because the obvious Rego fails open.

## Verification

Run `make check` before claiming a change works. It is what CI runs:
`opa fmt --fail`, `opa check --strict`, `make test`, `make coverage`, and `make
self-check`. Report the exact command and its outcome; never describe an unrun
check as passing.

`make coverage` and `make self-check` are gates, not advisory output. Do not
weaken, skip, or reconfigure them to make a change pass — if one fails, the
cause is in the change.

Needs `opa` and `conftest` on `PATH`; both honour `OPA=` / `CONFTEST=`.

## Adding or changing a rule

1. Rule IDs are `<DOMAIN>-<NNN>`, allocated sequentially per package. Two
   emission sites may share an ID when they are the same defect in different
   syntax (see K8S-007), but each site needs its own test.
2. Emit through the package's `finding` / `container_finding` helper, never a
   bare string — the aggregation pipeline reads the structured keys.
3. Add a fixture under `test/fixtures/<package>/<case>/` and an assertion in the
   package's `_test.rego`. `make coverage` fails if a rule body no test trips
   can emit an ID.
4. Add the rule to the table in `README.md`. If the reasoning is non-obvious,
   put it in `docs/design.md`, not in a long comment.

## Things that fail open

Be careful in these places; each has a test pinning it.

- Negative membership against `data.*` passes everything when the data never
  loaded. Comprehend into a set first, so an unloaded allowlist approves nothing.
- `not exc[field]` on a missing key is undefined, not true. Use `object.get`
  with a default.
- A `securityContext` fallback that treats an explicit `false` as absent lets a
  container override a compliant pod.
- Conftest defaults to the `main` namespace. A command missing `--namespace`
  reports zero findings and reads green.
- A traversal gap yields no containers and therefore no findings, so every rule
  test still passes. Traversal is tested directly in `lib_test.rego`.

## Style

- Comments are one or two lines, and explain a constraint or a non-obvious
  reason — not what the code says. Longer reasoning belongs in `docs/`.
- Rego is formatted by `opa fmt`; do not hand-format.
- In `.github/workflows/`, caller-controlled values reach a shell through `env:`,
  never through `${{ }}` inside a script body. Keep the comments that say so.
- Actions are pinned to a full commit SHA with the version in a trailing comment
  — this repo is subject to its own GHA-001 and GHA-002 via `make self-check`.

## Commits

Conventional Commits (`type(scope): subject`), imperative lowercase subject, no
trailing period. One purpose per commit; never mix a functional change with
unrelated formatting. Do not add agent attribution or `Co-Authored-By` trailers.
