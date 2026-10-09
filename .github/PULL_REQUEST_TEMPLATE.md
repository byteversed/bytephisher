## What this changes

<!-- One paragraph. What was wrong or missing, and what the change does. -->

## Why

<!-- The failure this prevents, or the capability it adds. -->

## Checks

- [ ] `make lint` is clean
- [ ] `make test-fast` is green
- [ ] `tests/test_e2e.py` is green (22 checks, real server + real capture store)
- [ ] `tools/gen_templates.py` re-run and `templates/` committed, if the generator
      or the brand data changed
- [ ] docs updated for any new flag, module or count
- [ ] no credential, private key, personal detail or operator host in the diff

## Notes for the reviewer

<!-- Anything you want a second pair of eyes on. -->
