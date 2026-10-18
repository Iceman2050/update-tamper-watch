# update-tamper-watch

Scheduled poller for critical vendors' **update manifests and checksums**. It alerts on any change — and specifically on changes that **revert within minutes**, the tamper-window signature of an ephemeral supply-chain attack.

## News hook (2026-10-18)

On 2026-10-16, Google Threat Intelligence Group and Mandiant disclosed that **UNC7017 tampered with AOMEI Backupper's own update servers in 5–10-minute windows** between May and July 2026. Attackers repeatedly changed the files Backupper fetches from the vendor's update servers (`down_html.ini`, `Notifycfg.ini`) so that any copy checking for an update *during a window* downloaded and ran a backdoor (CROSSROAD → SHINYROAD). Observed windows:

- **May 28, 2026** — 10 minutes (05:40–05:50 UTC)
- **July 16, 2026** — 6 minutes (08:33–08:39 UTC)
- **July 20, 2026** — 5 minutes (10:35–10:40 UTC)

The cruel detail: the files changed *back* within minutes, so the vendor's download page served genuine content almost all the time — and analysts dismissed real detections as false alarms. GTIG called it "effectively evading traditional point-in-time triage and automated file scanning."

Source: [The Hacker News — Attackers Tampered with AOMEI Backupper's Update Servers for Minutes to Deliver a Backdoor](http://thehackernews.com/2026/10/attackers-tampered-with-aomei.html)

This tool is the public detector that campaign was missing: poll fast enough (≤60s) and a 5-minute window cannot hide.

## How it works

1. You list vendor manifest URLs in a JSON config (`--init` writes an example).
2. Each poll fetches every manifest over HTTPS and records its SHA-256 in `state.json`, keeping a per-vendor hash timeline.
3. The detector classifies every observation:
   - `CHANGE` — hash differs from the last observation (logged as evidence).
   - **`TAMPER_WINDOW`** — the hash *reverted to an earlier hash* after an intervening different hash, with the whole divergence inside the configured window. This is the alert.
   - `CHANGE_PERSISTENT` — a change still in effect after the window elapsed with no revert.
   - `FETCH_ERROR` — the fetch failed (does not corrupt the timeline).

## How to run

```bash
# 1. Create a config
update-tamper-watch --init --config config.json

# 2. Or start from the AOMEI-pattern detection profile
cp profiles/aomei-pattern.json config.json

# 3. Poll once (run from cron every minute for the AOMEI pattern)
update-tamper-watch --config config.json

# 4. See the tamper-window signature on fixture manifests
update-tamper-watch --demo
```

Demo output (genuine → tampered → reverted, 5-minute divergence inside the 10-minute window):

```
{
  "type": "TAMPER_WINDOW",
  "vendor": "aomei-backupper-demo",
  "reverted_to": "d9d754a9...",
  "changed_to": "36a0a7af...",
  "window_seconds": 300.0,
  "evidence": "manifest served hash 36a0a7af... at 300.0 then reverted to d9d754a9... at 600.0; divergence lasted 300s (window 600s)"
}

demo complete: 1 TAMPER_WINDOW alert(s)
```

Exit codes: `0` no alerts, `2` tamper-window alert(s), `1` config error. Alerts append to `alerts.jsonl` with full evidence.

Cron example (poll every minute — the AOMEI pattern needs ≤60s resolution):

```cron
* * * * * cd /opt/update-tamper-watch && update-tamper-watch --config config.json >> poll.log 2>&1
```

## Development

```bash
pip install pytest
python -m pytest -v
```

## What it does NOT do

- It does not verify *signatures* — it detects *change patterns*. A vendor that legitimately ships a new release and rolls it back will also trigger `TAMPER_WINDOW`; the evidence log lets you tell the difference.
- It cannot see tampering that happened *between* your polls — poll interval must be shorter than the window you want to catch (the AOMEI windows were 5–10 minutes, hence 60s polling).
- It does not clean infected machines or block attacker infrastructure — it is a detector, not a responder. For the AOMEI campaign, GTIG/Mandiant's IOCs (storage-data[.]com, 8.210.84[.]56, 8.218.65[.]184, 47.239.60[.]117) still need blocking at the network layer.
- It does not cryptographically authenticate manifests the way vendors should (AOMEI's checksum sat inside the same unsigned file naming the download) — it watches from the outside.

## Built by Ingenious AI

Built by [Ingenious AI](https://github.com/Iceman2050) — the team shipping AI security tooling. Our platforms:

[DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard.)
[ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder.)
[TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch.)
[Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.)
[Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.)
[BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter.)
[ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker.)
[Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.)
[Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.)
[DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard.)
[ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI.)
