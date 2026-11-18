# Bearcorp threat hunt: detections and dashboard

28 detections (7 per role) written in Python + SQL against `dataset/bearcorp.db`, a dashboard to tune and triage them, and a `findings.json` exporter. Standard library only.

## Run

```bash
# optional but much faster: an indexed copy of the database (~10 GB, built once in ~90 s)
python3 hunt/make_indexes.py

# every detection with default settings -> findings.json (team 12), then check it
python3 hunt/run_all.py --team 12
python3 berkeley_hackathon_validate.py findings.json --data dataset/bearcorp.db

# dashboard on http://127.0.0.1:8800
python3 hunt/dashboard.py
```

The code uses `~/bearcorp-work/bearcorp.db` when it exists (set `BEARCORP_DB` to override) and falls back to `dataset/bearcorp.db`.

## Dashboard

- Left: the 28 hunts by role, with live finding counts.
- Middle: a hunt's description, its settings (thresholds, keyword lists, ignore lists), the detection SQL, and its findings. Change a setting and press **Run detection**; the table and counts update and show the change against the previous run.
- Click a finding to triage it: why it was flagged, what to do, every other finding on that host, the host's activity 30 minutes either side, and its USB activity.
- Untick a finding to leave it out of the export. **Export findings.json** merges every hunt's current results, drops duplicates and uses the team_id box.

## Files

| File | What it holds |
|---|---|
| `common.py` | database access, IP to host (including branch NAT), logged-in user, finding rows |
| `hunts_dns.py`, `hunts_web.py`, `hunts_endpoint.py`, `hunts_identity.py` | the detections, one function per hunt with its settings |
| `registry.py` | hunt registry and session grouping |
| `run_all.py` | runs everything and writes findings.json |
| `dashboard.py`, `dashboard.html` | the dashboard server and page |
| `explore.py`, `try.py` | small helpers used while writing detections |

## Judgement calls (all are settings in the dashboard)

- One finding per computer per attack session, timed at its first event.
- Scheduled uploads that repeat at the same time of day on 3+ days (archive.docvault-store.net) are treated as backups and skipped (`web1 > skip_scheduled`).
- The pentest account's nmap/dirb on SRV-02 is not reported.
- Look-alike update sites go to Endpoint hunt 7, long URLs to Web hunt 3, as the brief says.
