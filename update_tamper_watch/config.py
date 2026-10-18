"""Config loading. Config is plain JSON (stdlib only)."""

import json
import os

DEFAULT_ALERT_LOG = "alerts.jsonl"
DEFAULT_STATE = "state.json"


def load_config(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"config not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid JSON in {path}: {e}")
    if not isinstance(data, dict) or not isinstance(data.get("vendors"), list):
        raise ValueError(f"{path}: expected object with 'vendors' list")
    vendors = []
    for i, v in enumerate(data["vendors"]):
        if not isinstance(v, dict) or not v.get("name") or not v.get("manifest_url"):
            raise ValueError(f"{path}: vendors[{i}] needs 'name' and 'manifest_url'")
        vendors.append(
            {
                "name": str(v["name"]),
                "manifest_url": str(v["manifest_url"]),
                "poll_interval_seconds": int(v.get("poll_interval_seconds", 60)),
                "tamper_window_minutes": int(v.get("tamper_window_minutes", 10)),
                "timeout_seconds": int(v.get("timeout_seconds", 20)),
            }
        )
    return {
        "vendors": vendors,
        "state_file": data.get("state_file", DEFAULT_STATE),
        "alert_log": data.get("alert_log", DEFAULT_ALERT_LOG),
    }


def example_config():
    return {
        "state_file": "state.json",
        "alert_log": "alerts.jsonl",
        "vendors": [
            {
                "name": "aomei-backupper",
                "manifest_url": "https://www.ubackup.com/update/down_html.ini",
                "poll_interval_seconds": 60,
                "tamper_window_minutes": 10,
                "timeout_seconds": 20,
            },
            {
                "name": "example-vendor",
                "manifest_url": "https://example.com/update/manifest.ini",
                "poll_interval_seconds": 300,
                "tamper_window_minutes": 15,
                "timeout_seconds": 20,
            },
        ],
    }
