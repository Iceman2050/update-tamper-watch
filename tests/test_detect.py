"""Tests: tamper-window detection logic + CLI demo end-to-end."""

import json
import os

from update_tamper_watch import cli
from update_tamper_watch.detect import (
    CHANGE, CHANGE_PERSISTENT, TAMPER_WINDOW, process_observation,
)

A = "a" * 64
B = "b" * 64
C = "c" * 64


def fresh(name="vendor"):
    return {"name": name, "url": "https://example.com/m.ini", "timeline": []}


def test_first_observation_is_baseline_no_events():
    e = fresh()
    assert process_observation(e, 0.0, A, 10) == []
    assert len(e["timeline"]) == 1


def test_no_change_no_events():
    e = fresh()
    process_observation(e, 0.0, A, 10)
    assert process_observation(e, 60.0, A, 10) == []


def test_simple_change_emits_change_event():
    e = fresh()
    process_observation(e, 0.0, A, 10)
    events = process_observation(e, 60.0, B, 10)
    assert [ev["type"] for ev in events] == [CHANGE]
    assert events[0]["old_hash"] == A and events[0]["new_hash"] == B


def test_revert_inside_window_alerts_tamper():
    # AOMEI pattern: genuine -> tampered -> genuine, 5-min divergence.
    e = fresh("aomei-backupper")
    process_observation(e, 0.0, A, 10)
    process_observation(e, 300.0, B, 10)
    events = process_observation(e, 600.0, A, 10)
    kinds = [ev["type"] for ev in events]
    assert CHANGE in kinds
    assert TAMPER_WINDOW in kinds
    alert = next(ev for ev in events if ev["type"] == TAMPER_WINDOW)
    assert alert["reverted_to"] == A
    assert alert["changed_to"] == B
    assert alert["window_seconds"] == 300.0
    assert "evidence" in alert and alert["evidence"]


def test_revert_outside_window_is_not_tamper():
    e = fresh()
    process_observation(e, 0.0, A, 10)
    process_observation(e, 60.0, B, 10)
    events = process_observation(e, 3600.0, A, 10)  # 59 min later
    kinds = [ev["type"] for ev in events]
    assert TAMPER_WINDOW not in kinds
    assert CHANGE_PERSISTENT in kinds


def test_persistent_change_alerts_once():
    e = fresh()
    process_observation(e, 0.0, A, 10)
    ev1 = process_observation(e, 60.0, B, 10)   # change, inside window
    assert CHANGE_PERSISTENT not in [x["type"] for x in ev1]
    ev2 = process_observation(e, 900.0, C, 10)   # still changed, past window
    assert CHANGE_PERSISTENT in [x["type"] for x in ev2]
    ev3 = process_observation(e, 1800.0, C, 10)  # no new hash at all
    assert ev3 == []


def test_cli_demo_detects_tamper_window(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["--demo"])
    assert rc == cli.EXIT_ALERT
    out = capsys.readouterr().out
    assert "TAMPER_WINDOW" in out
    assert "demo complete: 1 TAMPER_WINDOW alert(s)" in out
    with open("demo-alerts.jsonl") as f:
        logged = [json.loads(line) for line in f]
    alerts = [e for e in logged if e["type"] == "TAMPER_WINDOW"]
    assert len(alerts) == 1
    assert alerts[0]["vendor"] == "aomei-backupper-demo"
    assert alerts[0]["window_seconds"] == 300.0


def test_cli_init_writes_example_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["--init", "--config", "config.json"])
    assert rc == cli.EXIT_OK
    assert os.path.exists("config.json")
    with open("config.json") as f:
        data = json.load(f)
    assert len(data["vendors"]) == 2


def test_cli_poll_with_file_urls(tmp_path, monkeypatch, capsys):
    # Real end-to-end poll cycle against fixture manifests over file://.
    monkeypatch.chdir(tmp_path)
    fix = os.path.join(os.path.dirname(__file__), "..", "fixtures", "manifests")
    v1 = "file://" + os.path.abspath(os.path.join(fix, "v1.ini"))
    cfg = {"state_file": "state.json", "alert_log": "alerts.jsonl",
           "vendors": [{"name": "demo", "manifest_url": v1,
                        "poll_interval_seconds": 60,
                        "tamper_window_minutes": 10,
                        "timeout_seconds": 20}]}
    with open("config.json", "w") as f:
        json.dump(cfg, f)
    rc = cli.main(["--config", "config.json"])
    assert rc == cli.EXIT_OK
    assert "no tamper-window alerts" in capsys.readouterr().out
    with open("state.json") as f:
        state = json.load(f)
    assert state["vendors"]["demo"]["last_hash"] == \
        "d9d754a94174cb7e412fe769ff52ba08c81da715470cabbd2198ad77cb697bd8"
