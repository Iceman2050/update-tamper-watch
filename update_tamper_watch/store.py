"""Persistent state: per-vendor hash timelines."""

import json
import os

MAX_TIMELINE = 64


def load_state(path):
    if not os.path.exists(path):
        return {"vendors": {}}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "vendors" not in data:
        return {"vendors": {}}
    return data


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def vendor_entry(state, name, url):
    vendors = state.setdefault("vendors", {})
    entry = vendors.setdefault(name, {"url": url, "timeline": []})
    entry["url"] = url
    return entry


def append_observation(entry, ts, digest):
    entry.setdefault("timeline", []).append({"ts": ts, "hash": digest})
    entry["timeline"] = entry["timeline"][-MAX_TIMELINE:]
    entry["last_hash"] = digest
    entry["last_seen"] = ts
