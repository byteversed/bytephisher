# BytePhisher — version / update check.
#
# Honest by design: with no update source configured this reports
# "not-configured" instead of pretending to be up to date. When a GitHub repo (or
# an explicit API URL) is set, it reads the latest release tag and compares.
#
# The startup notice is cached for 24h and runs in a background thread, so a slow
# or blocked network never delays a campaign.
import json
import os
import threading
import time

DEFAULT_API = "https://api.github.com/repos/{repo}/releases/latest"
CACHE_TTL = 24 * 3600


def _parse(v):
    """'v1.2.3' / '1.2.3' / '1.2' -> comparable tuple."""
    parts = str(v or "").strip().lstrip("vV").split(".")
    out = []
    for p in parts:
        num = ""
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        out.append(int(num) if num else 0)
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])


def is_newer(latest, current):
    return _parse(latest) > _parse(current)


def check_for_update(current_version, repo=None, api_url=None, timeout=6):
    """Return a dict describing the update state.

    status: 'update-available' | 'up-to-date' | 'not-configured' | 'unknown'
    """
    url = None
    if api_url:
        url = api_url
    elif repo:
        url = DEFAULT_API.format(repo=repo)
    if not url:
        return {"status": "not-configured", "current": current_version,
                "detail": "no update source configured (set update_repo in config "
                          "or pass --update-repo OWNER/REPO)"}
    try:
        from . import net
        data = net.fetch_json(url, timeout=timeout,
                              headers={"Accept": "application/vnd.github+json"})
        latest = (data.get("tag_name") or data.get("name")
                  or (data.get("version") if isinstance(data, dict) else None))
        if not latest:
            return {"status": "unknown", "current": current_version,
                    "detail": "update source returned no version field"}
        if is_newer(latest, current_version):
            return {"status": "update-available", "current": current_version,
                    "latest": str(latest),
                    "url": data.get("html_url") or url}
        return {"status": "up-to-date", "current": current_version, "latest": str(latest)}
    except Exception as e:
        return {"status": "unknown", "current": current_version,
                "detail": f"{type(e).__name__}: {e}"}


# ------------------------------------------------------------------ cache ----
def _cache_path(home):
    return os.path.join(home, "data", ".update_check.json")


def read_cache(home):
    try:
        with open(_cache_path(home), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def write_cache(home, result):
    try:
        os.makedirs(os.path.join(home, "data"), exist_ok=True)
        with open(_cache_path(home), "w", encoding="utf-8") as f:
            json.dump({**result, "checked_at": time.time()}, f, indent=2)
    except Exception:
        pass


def cached_or_check(home, current_version, repo=None, api_url=None, force=False):
    """Use the 24h cache unless `force`; stores fresh results."""
    if not force:
        cached = read_cache(home)
        if cached and time.time() - cached.get("checked_at", 0) < CACHE_TTL:
            return cached
    res = check_for_update(current_version, repo=repo, api_url=api_url)
    write_cache(home, res)
    return res


def start_background_check(home, current_version, repo=None, api_url=None,
                           on_result=None, force=False):
    """Non-blocking check for the startup notice."""
    def run():
        try:
            res = cached_or_check(home, current_version, repo=repo, api_url=api_url,
                                  force=force)
            if on_result:
                on_result(res)
        except Exception:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t
