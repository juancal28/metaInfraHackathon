# Bearcorp threat hunt (team 12)

Detections, dashboard and findings for the Bearcorp threat hunt.

- `findings.json`: all 28 detections at their default settings, team_id 12 (513 findings, passes the validator).
- `hunt/`: the detections, the dashboard and how to run them. Start with [hunt/README.md](hunt/README.md).

The dataset is not in this repository. Put these files in the unzipped `bearcorp-threat-hunt` folder from the kit, next to `dataset/bearcorp.db` and `berkeley_hackathon_validate.py`, then:

```bash
python3 hunt/dashboard.py        # http://127.0.0.1:8800
```
