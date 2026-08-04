# Requires opa and conftest on PATH; override to point elsewhere.
OPA      ?= opa
CONFTEST ?= conftest

# Fixtures load as data.fixtures.* because the load root is test/ and OPA
# derives data paths from the directory structure below it. Files under data/
# sit at the load root, so their top-level keys land directly on data.
POLICY_ARGS := policy/ test/ data/

.PHONY: test
test: ## Run the Rego unit tests
	$(OPA) test $(POLICY_ARGS) -v
	$(CONFTEST) verify -p policy --data test/ --data data/

.PHONY: fmt
fmt: ## Format Rego sources in place
	$(OPA) fmt -w policy/

# Runs the suite a second time, under --coverage, because the gate needs line
# coverage and `make test` needs verbose output. A second `opa test` over this
# policy set costs under a second; keeping the two targets independently
# runnable is worth more than sharing the run.
.PHONY: coverage
coverage: ## Fail if any rule ID has no test that trips it
	OPA=$(OPA) ./scripts/rule-coverage.sh

# Belongs in `check` rather than only in CI. The violation this catches is
# introduced by editing a file in this repo, so the reviewer who edits it is
# the person who should see it go red — a gate that only fires after push
# teaches people to push and wait.
.PHONY: self-check
self-check: ## Evaluate this repo's own workflows and inventory against its policies
	CONFTEST=$(CONFTEST) ./scripts/self-check.sh

.PHONY: check
check: ## Verify formatting, type-check, test, rule coverage, and self-enforcement
	$(OPA) fmt --fail --list policy/
	$(OPA) check --strict policy/
	$(MAKE) test
	$(MAKE) coverage
	$(MAKE) self-check

.PHONY: inventory
inventory: ## Write repo-inventory.json for the policy/repo package
	./scripts/repo-inventory.sh . > repo-inventory.json
