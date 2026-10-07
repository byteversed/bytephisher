# BytePhisher — link helpers: QR codes and link preview metadata.
#
# QR codes matter in real awareness campaigns (posters, badges, WhatsApp
# stickers). segno is pure Python with no runtime deps; if it is missing we
# degrade gracefully instead of breaking the run.
import os


def qr_png(url, path=None, scale=6, border=2):
    """Write a PNG QR code for `url`. Returns the path, or None if segno
    isn't installed (the caller decides whether that is fatal)."""
    try:
        import segno
    except ImportError:
        return None
    qr = segno.make(url, error="m")
    if path is None:
        path = os.path.join("data", "qr.png")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    qr.save(path, scale=scale, border=border)
    return path


def qr_svg(url, path=None):
    """SVG variant for print-quality campaign material."""
    try:
        import segno
    except ImportError:
        return None
    if path is None:
        path = os.path.join("data", "qr.svg")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    segno.make(url, error="m").save(path, scale=6, border=2)
    return path


def qr_ascii(url):
    """Terminal preview: returns the QR as text, or None without segno.
    (segno's terminal() writes to stdout and returns None — capture it.)"""
    try:
        import segno
    except ImportError:
        return None
    import io
    buf = io.StringIO()
    segno.make(url, error="m").terminal(compact=True, out=buf)
    return buf.getvalue()
