# Cyber Threat Dashboard - Python (pandas + Streamlit)

The pro-grade version of the browser demo: real log parsing, incident detection and IP analytics computed by pandas, presented in Streamlit.

## Stack

- **pandas / numpy** - syslog (sshd/ufw) and CSV ingestion, hourly timelines, per-IP aggregation
- **Detection engine** - brute force (burst of failures from one IP), password spraying (one IP probing many usernames), distributed guessing (one user targeted from many IPs in a tight window)
- **Streamlit** - KPIs, severity-highlighted incident table, event timeline, top attacking IPs, raw event explorer

## Run locally

```
pip install -r requirements.txt
streamlit run app.py
```

## Tests

```
python3 tests/test_threats.py     # or: python3 -m pytest tests/ -q
```

Covers syslog parsing (sshd/ufw lines, noise skipping), CSV loading, planted brute-force and spray detection, zero alerts on a clean log, KPI aggregation, and unparseable-input errors.

## Honest limits

- Threshold-based heuristics, not a SIEM; tune thresholds to your baseline.
- No IP geolocation (no external calls).

## Layout

- `threats.py` - pure logic (no Streamlit imports), fully unit tested
- `app.py` - Streamlit UI
- `tests/test_threats.py` - unit tests
