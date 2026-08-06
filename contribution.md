# Contributing

## Development

Install [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa) and
[`conftest`](https://www.conftest.dev/install/), then run:

```sh
make check
```

This is the same verification used by CI. It checks formatting, strict Rego
types, tests, rule coverage, and this repository's own policy compliance.

The individual checks are:

```sh
make test        # opa test + conftest verify
make coverage    # fail if any rule has no test that trips it
make self-check  # evaluate this repo's own workflows and inventory
make check       # all checks above
```

All make targets accept `OPA=` / `CONFTEST=` overrides. See
[docs/testing.md](docs/testing.md) for details.

## Layout

```
policy/<package>/*.rego          policies, one package per domain
policy/<package>/*_test.rego     unit tests, colocated
test/fixtures/<package>/<case>/  fixture documents
data/<package>.yaml              config and allowlists
scripts/                         helpers used by make and workflows
docs/                            design notes
```

## Adding or changing a rule

Keep each rule in its package under `policy/`. Rule IDs use the
`<DOMAIN>-<NNN>` format and are allocated sequentially within that package.
Emit findings with the package's `finding` or `container_finding` helper so
the aggregation pipeline receives structured metadata.

For every new emission site:

1. Add a fixture under `test/fixtures/<package>/<case>/`.
2. Add an assertion in the package's `_test.rego` that reaches the emission.
3. Add the rule to the rules table in `README.md`.
4. Run `make check`.

If a rule depends on a non-obvious policy constraint, document the reasoning in
`docs/design.md` rather than in a long code comment.

### Running a package directly

Conftest defaults to the `main` namespace, so name the package explicitly.
`--data data/` is required for packages that read allowlists.

```sh
conftest test --policy policy --data data/ --namespace kubernetes rendered.yaml
conftest test --policy policy --data data/ --namespace github .github/workflows/test.yml
make inventory
conftest test --policy policy --namespace repo repo-inventory.json
```

Widening an allowlist is a review of a YAML file, not a change to Rego.

## Releasing

`.github/workflows/release.yml` is triggered manually from `master`, with a
version such as `v1.2.0`. It re-runs `make self-check` and `make check`, then
creates the tag and GitHub release.

There is no floating `v1` alias. Consumers pin `policy-ref` to a tag and must
explicitly bump it when upgrading. Releases are cut from `master` only.

## Pull requests

Keep changes focused and include the problem, the solution, and the exact
verification command and result. Use a Conventional Commit message, for
example:

```text
fix(kubernetes): reject writable root filesystems
```
