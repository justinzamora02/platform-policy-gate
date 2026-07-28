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

.PHONY: check
check: ## Verify formatting, type-check, and test
	$(OPA) fmt --fail --list policy/
	$(OPA) check --strict policy/
	$(MAKE) test

.PHONY: inventory
inventory: ## Write repo-inventory.json for the policy/repo package
	./scripts/repo-inventory.sh . > repo-inventory.json
