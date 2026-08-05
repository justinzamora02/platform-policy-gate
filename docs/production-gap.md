# Production gap

What this demo does not do, and what would change with real infrastructure behind
it. Knowing the limits of your own system is worth more than pretending they
don't exist.

- **CI is not an enforcement boundary.** Anything not applied through this
  pipeline is unchecked. In production the authoritative control is an admission
  controller (Kyverno or Gatekeeper); this pipeline would become fast feedback in
  front of it, and the Kubernetes policies would be authored for the admission
  layer and run in CI from the same source to avoid drift.
- **Values coverage is partial.** Charts are rendered against the `values*.yaml`
  files committed in the repo. Real deployment values often live in a GitOps repo
  or ArgoCD `Application`, so a green check proves the committed values are
  compliant — nothing more. The output states which values files were evaluated.
- **Adoption is voluntary here.** In an org, the check would be required via an
  organization ruleset, and new rules would need a `warn → deny` lifecycle with
  lead time so a policy change doesn't break every repo on merge day.
- **Findings are surfaced as job summaries, not SARIF.** SARIF upload to code
  scanning would be the production choice; Conftest has no native SARIF output,
  so it requires a converter.
