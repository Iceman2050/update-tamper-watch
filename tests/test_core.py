"""Tests: fetcher, store, config."""

import hashlib
import json
import os

import pytest

from update_tamper_watch.config import example_config, load_config
from update_tamper_watch.fetcher import fetch_hash
from update_tamper_watch.store import load_state, save_state, vendor_entry

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures", "manifests")
V1_SHA = "d9d754a94174cb7e412fe769ff52ba08c81da715470cabbd2198ad77cb697bd8"
V2_SHA = "36a0a7afa50a75353fd659ac036f0eb1cae5f082a397853eca420988b63e992e"


def file_url(name):
    return "file://" + os.path.abspath(os.path.join(FIX, name))


def test_fetch_hash_of_fixture_file():
    digest, err = fetch_hash(file_url("v1.ini"))
    assert err is None
    assert digest == V1_SHA


def test_fetch_hash_distinguishes_versions():
    d1, _ = fetch_hash(file_url("v1.ini"))
    d2, _ = fetch_hash(file_url("v2.ini"))
    assert d1 == V1_SHA and d2 == V2_SHA and d1 != d2


def test_fetch_hash_missing_file_returns_error():
    digest, err = fetch_hash(file_url("does-not-exist.ini"))
    assert digest is None
    assert err is not None


def test_store_round_trip(tmp_path):
    p = str(tmp_path / "state.json")
    state = load_state(p)
    entry = vendor_entry(state, "acme", "https://acme.example/manifest.ini")
    entry["timeline"].append({"ts": 1.0, "hash": "abc"})
    save_state(p, state)
    reloaded = load_state(p)
    assert reloaded["vendors"]["acme"]["timeline"][0]["hash"] == "abc"


def test_load_state_missing_file_is_empty(tmp_path):
    assert load_state(str(tmp_path / "nope.json")) == {"vendors": {}}


def test_load_config_example_valid(tmp_path):
    p = str(tmp_path / "config.json")
    with open(p, "w") as f:
        json.dump(example_config(), f)
    cfg = load_config(p)
    assert len(cfg["vendors"]) == 2
    assert cfg["vendors"][0]["tamper_window_minutes"] == 10


def test_load_config_missing_file():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/config.json")


def test_load_config_bad_shape(tmp_path):
    p = str(tmp_path / "bad.json")
    with open(p, "w") as f:
        json.dump({"vendors": [{"name": "x"}]}, f)
    with pytest.raises(ValueError, match="manifest_url"):
        load_config(p)


def test_aomei_profile_parses():
    prof = os.path.join(os.path.dirname(__file__), "..",
                        "profiles", "aomei-pattern.json")
    with open(prof) as f:
        data = json.load(f)
    assert data["vendors"][0]["tamper_window_minutes"] == 10
    assert data["vendors"][0]["poll_interval_seconds"] == 60
    assert "thehackernews" in data["source"]
    assert len(data["observed_windows"]) == 3
