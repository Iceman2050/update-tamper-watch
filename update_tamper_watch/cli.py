"""CLI: poll vendor update manifests, detect tamper-window signatures."""

import argparse
import json
import os
import sys
import time

from .config import example_config, load_config
from .detect import CHANGE, FETCH_ERROR, TAMPER_WINDOW, process_observation
from .fetcher import fetch_hash
from .store import load_state, save_state, vendor_entry

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ALERT = 2


def write_alerts(alert_log, events):
    if not events:
        return
    with open(alert_log, "a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def poll_once(config, state, now=None, fetcher=None):
    """One poll cycle over all vendors. Returns (alert_events, fetch_errors)."""
    now = time.time() if now is None else now
    fetcher = fetch_hash if fetcher is None else fetcher
    alerts, errors = [], []
    for v in config["vendors"]:
        digest, err = fetcher(v["manifest_url"],
                             timeout_seconds=v["timeout_seconds"])
        entry = vendor_entry(state, v["name"], v["manifest_url"])
        entry["name"] = v["name"]
        if err:
            errors.append({"type": FETCH_ERROR, "ts": now,
                           "vendor": v["name"], "error": err})
            continue
        events = process_observation(entry, now, digest,
                                     v["tamper_window_minutes"])
        alerts.extend(e for e in events if e["type"] == TAMPER_WINDOW)
        # CHANGE / CHANGE_PERSISTENT are evidence too: log them as well.
        write_alerts(config["alert_log"],
                     [e for e in events if e["type"] != TAMPER_WINDOW])
    write_alerts(config["alert_log"], alerts)
    return alerts, errors


def run_demo(alert_log="demo-alerts.jsonl"):
    """End-to-end demo of the AOMEI tamper-window pattern on fixtures.

    Timeline: genuine manifest at t=0, tampered at t=300s, reverted to
    genuine at t=600s — a 5-minute divergence inside the 10-minute AOMEI
    window. Uses file:// fixture manifests (real file I/O, no mocks).
    """
    base = os.path.join(os.path.dirname(__file__), "..", "fixtures", "manifests")
    v1 = "file://" + os.path.abspath(os.path.join(base, "v1.ini"))
    v2 = "file://" + os.path.abspath(os.path.join(base, "v2.ini"))
    config = {"vendors": [{"name": "aomei-backupper-demo",
                           "manifest_url": v1,
                           "poll_interval_seconds": 60,
                           "tamper_window_minutes": 10,
                           "timeout_seconds": 20}],
              "state_file": ":memory:", "alert_log": alert_log}
    state = {"vendors": {}}
    if os.path.exists(alert_log):
        os.remove(alert_log)

    # Scripted timeline: v1 -> v2 (tampered) -> v1 (reverted), 5-min divergence.
    script = [(0, v1), (300, v2), (600, v1)]
    all_alerts = []
    for ts, url in script:
        config["vendors"][0]["manifest_url"] = url
        alerts, errors = poll_once(config, state, now=float(ts))
        assert not errors, errors
        all_alerts.extend(alerts)
    return all_alerts


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="update-tamper-watch",
        description="Poll vendor update manifests and alert on changes — "
                    "especially changes that revert within minutes "
                    "(the tamper-window signature).",
    )
    parser.add_argument("--config", default="config.json",
                        help="JSON config listing vendor manifest URLs")
    parser.add_argument("--state", default=None,
                        help="state file (defaults to config's state_file)")
    parser.add_argument("--init", action="store_true",
                        help="write an example config.json and exit")
    parser.add_argument("--demo", action="store_true",
                        help="run the AOMEI-pattern demo on fixture manifests")
    args = parser.parse_args(argv)

    if args.init:
        with open(args.config, "w", encoding="utf-8") as f:
            json.dump(example_config(), f, indent=2)
        print(f"wrote example config to {args.config}")
        return EXIT_OK

    if args.demo:
        alerts = run_demo()
        for a in alerts:
            print(json.dumps(a, indent=2))
        print(f"\ndemo complete: {len(alerts)} TAMPER_WINDOW alert(s)")
        return EXIT_ALERT if alerts else EXIT_OK

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    state_file = args.state or config["state_file"]
    state = load_state(state_file)
    alerts, errors = poll_once(config, state)
    save_state(state_file, state)

    for e in errors:
        print(f"[FETCH_ERROR] {e['vendor']}: {e['error']}", file=sys.stderr)
    for a in alerts:
        print(f"[TAMPER_WINDOW] {a['vendor']}: {a['evidence']}")
    if not alerts and not errors:
        print("no tamper-window alerts; state updated")
    return EXIT_ALERT if alerts else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
