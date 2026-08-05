# Testing and self-enforcement

```sh
make test        # opa test + conftest verify
make coverage    # fail if any rule has no test that trips it
make self-check  # evaluate this repo's own workflows and inventory against these rules
make check       # all of the above, plus formatting and a strict type check (what CI runs)
```

All of them accept `OPA=` / `CONFTEST=` overrides if your binaries live
elsewhere.

## Fixtures

Fixtures are loaded by directory, not by filename: `opa test policy/ test/ data/`
puts `test/fixtures/repo/license-missing/inventory.yaml` at
`data.fixtures.repo["license-missing"]`. Files directly under a load root merge
at the top, so `data/gha.yaml` lands on `data.gha` — one config document per
policy package, keyed separately from the policy namespace it configures.

## Rule coverage

`scripts/rule-coverage.sh` fails the build when a policy can emit a rule ID that
no test ever trips.

Grepping the IDs out of `policy/` and out of `policy/*_test.rego` would report
full coverage forever — the ID an assertion names is the same string the rule
defines, and a comment mentioning a rule reads the same as the rule. So the two
sides come from two tools instead:

| Side | Source | Why |
|---|---|---|
| IDs a policy can emit | `opa parse --json-include locations` | an AST has no comments in it |
| IDs a test actually reached | `opa test --coverage` | a deny body's `msg := ...` is only covered when the rule fired |

That last distinction is what the gate turns on. The unit is the emission site,
not the ID — K8S-007 denies `:latest` and an untagged image from two separate
rule bodies, and each needs its own test. Both sides are discovered at run time,
so a new package is under the gate as soon as it is committed.

The script assumes a rule ID literal appears inside the rule that emits it; a
package keeping its IDs in a lookup table would be measured on the table instead.

## Self-enforcement

`scripts/self-check.sh` runs the published rules against this repository. The
tests prove a rule fires correctly against a fixture; they say nothing about
whether the repo shipping the rule obeys it. Without this, `uses:
actions/checkout@v5` could land in `.github/workflows/` here, every fixture would
still pass, and a repository whose whole argument is policy-as-code would merge
an unpinned action behind a green check.

It evaluates two namespaces, because the two packages read two different kinds of
document: `github` over `.github/workflows/`, and `repo` over an inventory
generated from the working tree by `scripts/repo-inventory.sh`. Both run before
the script exits, so one run reports everything wrong rather than the first thing.

The inventory goes to a temp directory — it is an artifact of the current tree,
not a source file — so a self-check run never dirties `git status`. `make
inventory` remains the way to write one out for inspection
(`repo-inventory.json`, gitignored).

A path matching no files is an error from Conftest and is left to fail. If
`.github/workflows/` is ever renamed or emptied, this must go red rather than
congratulate the repo on having no violations.

Self-check is part of `make check`, and also a step of its own in CI, ahead of
`make check`. The duplicated run costs under a second and buys a distinction
worth seeing in the job summary: `make check` red means the policies are broken,
and self-check red means the policies are fine and *this repository* violates
them.
