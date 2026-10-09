import os
import sys

# BytePhisher - core package

def asset_path(name):
    """Resolve a browser-side asset (`intel.js`, `sw.js`).

    These files ship INSIDE the package (`core/assets/`) so that a wheel carries them.
    The repository root also held an `assets/` directory historically and an installed
    distribution may have put them under `sys.prefix`, so both are still tried. A missing
    file raises with the paths it looked in, because the failure this prevents - a
    collector that cannot be served, silently - is otherwise invisible.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [os.path.join(here, "assets", name),
                  os.path.join(os.path.dirname(here), "assets", name),
                  os.path.join(sys.prefix, "assets", name)]
    for c in candidates:
        if os.path.isfile(c):
            return c
    raise FileNotFoundError(
        f"{name} not found (looked in: {', '.join(candidates)}); the browser-side assets "
        f"live in core/assets/ and must be declared as package-data for the `core` "
        f"package, or a wheel installs without them")



__version__ = "0.1.0"
