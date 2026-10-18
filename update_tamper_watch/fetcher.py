"""Fetch a manifest URL and hash its bytes (real I/O via urllib)."""

import hashlib
import urllib.error
import urllib.request


def fetch_hash(url, timeout_seconds=20):
    """Return (sha256_hex, None) on success or (None, error_string) on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "update-tamper-watch/0.1.0"})
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            body = resp.read()
        return hashlib.sha256(body).hexdigest(), None
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:
        return None, f"{type(e).__name__}: {e}"
