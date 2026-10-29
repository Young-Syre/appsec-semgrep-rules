SEMGREP ?= semgrep
RULES   ?= rules
TESTS   ?= tests

.PHONY: help test validate lint all ci

help:
	@echo "make validate  - check every rule parses and has well-formed metadata"
	@echo "make test      - run the fixture suite (semgrep --test)"
	@echo "make lint      - validate + YAML syntax + metadata completeness"
	@echo "make all       - validate, lint, test"

validate:
	$(SEMGREP) --validate --config $(RULES)

test:
	$(SEMGREP) --test --config $(RULES) $(TESTS)

lint: validate
	python3 scripts/lint_metadata.py $(RULES)

all: validate lint test

ci: all
