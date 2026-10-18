"""Tamper-window detection.

The signature we hunt: a manifest hash CHANGES and then REVERTS to a
previously-seen hash within `window_minutes` — the exact pattern GTIG and
Mandiant described for UNC7017's tampering of AOMEI Backupper's update
servers (5-10 minute windows, May-Jul 2026).

Events emitted:
- "CHANGE": hash differs from the previous observation.
- "TAMPER_WINDOW": hash reverted to an earlier hash after an intervening
  different hash, with the whole divergence inside the window. This is the
  alert that matters: it means the server briefly served different content.
- "CHANGE_PERSISTENT": a change that is still in effect after the window
  elapsed with no revert (emitted once per divergence).
- "FETCH_ERROR": the fetch failed.
"""

TAMPER_WINDOW = "TAMPER_WINDOW"
CHANGE = "CHANGE"
CHANGE_PERSISTENT = "CHANGE_PERSISTENT"
FETCH_ERROR = "FETCH_ERROR"


def _divergence_start(timeline, current_hash, prev_hash):
    """When did the current divergence from prev_hash begin?"""
    for obs in reversed(timeline):
        if obs["hash"] == prev_hash:
            return obs["ts"]
    return timeline[0]["ts"] if timeline else None


def process_observation(entry, ts, digest, window_minutes):
    """Process one poll observation. Returns a list of event dicts.

    `entry` is the vendor's state entry (mutated: timeline appended).
    Pure logic over (ts, hash) — no I/O, fully deterministic.
    """
    from .store import append_observation

    events = []
    timeline = entry.get("timeline", [])
    window_s = window_minutes * 60

    if not timeline:
        append_observation(entry, ts, digest)
        return events  # first sighting: baseline, no alert

    prev_hash = timeline[-1]["hash"]
    if digest == prev_hash:
        # No change, but a late revert may have been pending? No: identical
        # hashes mean the timeline tail already reflects this state.
        append_observation(entry, ts, digest)
        return events

    # A change happened.
    events.append({
        "type": CHANGE,
        "ts": ts,
        "vendor": entry.get("name", "?"),
        "old_hash": prev_hash,
        "new_hash": digest,
    })

    # Did it revert to an earlier hash after an intervening different one?
    earlier_hashes = {obs["hash"] for obs in timeline[:-1]}
    if digest in earlier_hashes:
        div_start = _divergence_start(timeline, digest, prev_hash)
        span = ts - div_start if div_start is not None else None
        if span is not None and span <= window_s:
            events.append({
                "type": TAMPER_WINDOW,
                "ts": ts,
                "vendor": entry.get("name", "?"),
                "reverted_to": digest,
                "changed_to": prev_hash,
                "changed_at": div_start,
                "reverted_at": ts,
                "window_seconds": span,
                "window_limit_seconds": window_s,
                "evidence": (
                    f"manifest served hash {prev_hash[:12]}... at {div_start} "
                    f"then reverted to {digest[:12]}... at {ts}; divergence "
                    f"lasted {span:.0f}s (window {window_s:.0f}s)"
                ),
            })
        elif span is not None:
            events.append({
                "type": CHANGE_PERSISTENT,
                "ts": ts,
                "vendor": entry.get("name", "?"),
                "old_hash": prev_hash,
                "new_hash": digest,
                "note": f"reverted to an earlier hash after {span:.0f}s, "
                        f"outside the {window_s:.0f}s tamper window",
            })
    else:
        # Brand-new hash never seen before: check whether a previous
        # divergence has now exceeded the window without reverting.
        div_start = _divergence_start(timeline, digest, prev_hash)
        if (div_start is not None and ts - div_start > window_s
                and not entry.get("persistent_alerted_for", "") == prev_hash):
            events.append({
                "type": CHANGE_PERSISTENT,
                "ts": ts,
                "vendor": entry.get("name", "?"),
                "old_hash": prev_hash,
                "new_hash": digest,
                "note": f"change in effect for {ts - div_start:.0f}s with no "
                        f"revert inside the {window_s:.0f}s window",
            })
            entry["persistent_alerted_for"] = prev_hash

    append_observation(entry, ts, digest)
    return events
