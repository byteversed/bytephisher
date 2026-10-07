# BytePhisher — common tasks. `make help` lists everything.
PY := ./.venv/bin/python
PIP := ./.venv/bin/pip

.PHONY: help venv install templates test test-fast lint run report clean distclean

help:
	@echo "make install      create .venv, install deps, generate templates"
	@echo "make templates    (re)generate the template library"
	@echo "make test         full suite incl. live internet/tunnel/SMTP tests"
	@echo "make test-fast    skip the live suite"
	@echo "make run          local-only run on :8080 (no tunnel)"
	@echo "make report       write data/report.html from the capture DB"
	@echo "make probe        probe every tunneler against the real internet"
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

run:
	$(PY) bytephisher.py -o google -m test -p 8080

report:
	$(PY) tools/report.py --out data/report.html

probe:
	$(PY) tools/probe_tunnels.py

clean:
	rm -rf **/__pycache__ .pytest_cache logs/*.log
	find . -name '*.pyc' -delete

distclean: clean
	rm -rf .venv data logs templates bin
