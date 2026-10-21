"""Cyber threat log analysis: parsing, aggregation, brute-force detection.

Pure-logic module, no Streamlit imports.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass

import numpy as np
import pandas as pd

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class ThreatReport:
    events: pd.DataFrame       # parsed events: ts, source_ip, user, kind, severity, raw
    kpis: dict
    alerts: pd.DataFrame       # detected incidents
    by_kind: pd.DataFrame
    timeline: pd.DataFrame     # hour -> counts by severity
    top_ips: pd.DataFrame


SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
SSH_ACCEPT = re.compile(r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)")
INVALID_USER = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")
UFW_BLOCK = re.compile(r"UFW BLOCK.*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)")
SYSLOG_TS = re.compile(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)")


def _classify_line(line: str):
    """Return (user, ip, kind, severity) or None for unrecognized lines."""
    if m := SSH_FAIL.search(line):
        return m.group(1), m.group(2), "ssh_failed", "medium"
    if m := SSH_ACCEPT.search(line):
        return m.group(1), m.group(2), "ssh_login", "info"
    if m := INVALID_USER.search(line):
        return m.group(1), m.group(2), "invalid_user", "low"
    if m := UFW_BLOCK.search(line):
        return "-", m.group(1), "firewall_block", "low"
    return None


def parse_syslog(text: str, year: int = 2026) -> pd.DataFrame:
    """Parse syslog-style lines (sshd/ufw). Unrecognized lines are skipped."""
    rows = []
    current_ts = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if m := SYSLOG_TS.match(line):
            current_ts = pd.to_datetime(f"{m.group(1)} {year}", format="%b %d %H:%M:%S %Y", errors="coerce")
        parsed = _classify_line(line)
        if parsed and current_ts is not None and not pd.isna(current_ts):
            user, ip, kind, sev = parsed
            rows.append({"ts": current_ts, "source_ip": ip, "user": user,
                         "kind": kind, "severity": sev, "raw": line[:200]})
    if not rows:
        raise ValueError("No recognizable syslog events found (sshd/ufw format expected).")
    return pd.DataFrame(rows)


def load_events(source, fmt: str = "auto") -> pd.DataFrame:
    """Load events from CSV (ts, source_ip, user, kind, severity) or syslog text."""
    data = source.read() if hasattr(source, "read") else source
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    head = data.lstrip()[:200].lower()
    if fmt == "csv" or (fmt == "auto" and "source_ip" in head and "," in head.splitlines()[0]):
        df = pd.read_csv(io.StringIO(data))
        df.columns = [c.strip().lower() for c in df.columns]
        need = {"ts", "source_ip", "kind", "severity"}
        missing = need - set(df.columns)
        if missing:
            raise ValueError(f"Missing required column(s): {', '.join(sorted(missing))}")
        df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
        df = df.dropna(subset=["ts"]).reset_index(drop=True)
        if "user" not in df.columns:
            df["user"] = "-"
        if "raw" not in df.columns:
            df["raw"] = ""
        if df.empty:
            raise ValueError("No valid rows after parsing.")
        return df
    return parse_syslog(data)


def detect_alerts(events: pd.DataFrame, bf_threshold: int = 8, bf_window_min: int = 10,
                  spray_threshold: int = 6) -> pd.DataFrame:
    """Incident detection: brute force, password spraying, fan-out probing."""
    alerts = []
    fails = events[events["kind"].isin(["ssh_failed", "invalid_user"])].sort_values("ts")
    # brute force: one IP, many failures in a short window
    for ip, grp in fails.groupby("source_ip"):
        if len(grp) < bf_threshold:
            continue
        window = pd.Timedelta(minutes=bf_window_min)
        times = grp["ts"].tolist()
        best = 0
        for i, t0 in enumerate(times):
            n = sum(1 for t in times[i:] if t - t0 <= window)
            best = max(best, n)
        if best >= bf_threshold:
            users = grp["user"].nunique()
            alerts.append({
                "kind": "brute_force", "source_ip": ip, "attempts": int(len(grp)),
                "peak_in_window": int(best), "users_targeted": int(users),
                "severity": "critical" if best >= bf_threshold * 3 else "high",
                "detail": f"{best} failed logins within {bf_window_min} min from {ip}",
            })
    # password spraying: one IP, one password pattern across many users (many users, low per-user count)
    for ip, grp in fails.groupby("source_ip"):
        users = grp["user"].nunique()
        if users >= spray_threshold and ip not in {a["source_ip"] for a in alerts}:
            alerts.append({
                "kind": "password_spray", "source_ip": ip, "attempts": int(len(grp)),
                "peak_in_window": int(users), "users_targeted": int(users),
                "severity": "high",
                "detail": f"{users} distinct usernames probed from {ip}",
            })
    # distributed guessing: many distinct IPs failing against one user within a tight window
    window = pd.Timedelta(minutes=30)
    for user, grp in fails[fails["user"] != "-"].groupby("user"):
        if grp["source_ip"].nunique() < 5:
            continue
        times = grp["ts"].tolist()
        hit = 0
        for i, t0 in enumerate(times):
            ips_in = grp[(grp["ts"] >= t0) & (grp["ts"] <= t0 + window)]["source_ip"].nunique()
            hit = max(hit, ips_in)
        if hit >= 5:
            ips = grp["source_ip"].nunique()
            alerts.append({
                "kind": "distributed_guess", "source_ip": f"{ips} IPs", "attempts": int(len(grp)),
                "peak_in_window": int(hit), "users_targeted": 1,
                "severity": "medium",
                "detail": f"user '{user}' targeted from {hit} distinct IPs within 30 min",
            })
    cols = ["kind", "source_ip", "attempts", "peak_in_window", "users_targeted", "severity", "detail"]
    return pd.DataFrame(alerts, columns=cols).sort_values("attempts", ascending=False).reset_index(drop=True) if alerts else pd.DataFrame(columns=cols)


def build_report(events: pd.DataFrame) -> ThreatReport:
    alerts = detect_alerts(events)
    by_kind = events.groupby("kind").size().rename("count").reset_index().sort_values("count", ascending=False)
    tl = (
        events.assign(hour=events["ts"].dt.floor("h"))
        .groupby(["hour", "severity"]).size().unstack(fill_value=0).reset_index()
    )
    top_ips = (
        events.groupby("source_ip")
        .agg(events=("kind", "size"), failures=("kind", lambda s: int(s.isin(["ssh_failed", "invalid_user"]).sum())),
             users=("user", "nunique"), first_seen=("ts", "min"), last_seen=("ts", "max"))
        .sort_values("events", ascending=False).head(15).reset_index()
    )
    kpis = {
        "events": int(len(events)),
        "unique_ips": int(events["source_ip"].nunique()),
        "failed_logins": int(events["kind"].isin(["ssh_failed", "invalid_user"]).sum()),
        "alerts": int(len(alerts)),
        "critical": int((alerts["severity"] == "critical").sum()) if len(alerts) else 0,
        "span_hours": round(max((events["ts"].max() - events["ts"].min()).total_seconds() / 3600, 0.01), 1),
    }
    return ThreatReport(events=events, kpis=kpis, alerts=alerts, by_kind=by_kind,
                        timeline=tl, top_ips=top_ips)


def sample_log(seed: int = 21) -> str:
    """Synthetic syslog with planted brute-force and spray attacks."""
    rng = np.random.default_rng(seed)
    lines = []
    day = "Oct 21"
    legit_users = ["akash", "deploy", "admin", "git", "ubuntu"]
    t = pd.Timestamp("2026-10-21 00:05")
    for _ in range(420):
        t += pd.Timedelta(seconds=int(rng.integers(30, 400)))
        ts = t.strftime(f"{day} %H:%M:%S")
        roll = rng.random()
        if roll < 0.55:
            user = rng.choice(legit_users)
            ip = f"10.0.{rng.integers(0, 5)}.{rng.integers(2, 250)}"
            lines.append(f"{ts} server sshd[811]: Accepted publickey for {user} from {ip} port 51022 ssh2")
        elif roll < 0.8:
            user = rng.choice(legit_users + ["oracle", "test", "pi"])
            ip = f"103.{rng.integers(1, 250)}.{rng.integers(1, 250)}.{rng.integers(1, 250)}"
            lines.append(f"{ts} server sshd[811]: Failed password for {user} from {ip} port 51023 ssh2")
        else:
            ip = f"45.{rng.integers(1, 250)}.{rng.integers(1, 250)}.{rng.integers(1, 250)}"
            lines.append(f"{ts} server kernel: [UFW BLOCK] IN=eth0 SRC={ip} DPT={int(rng.choice([22, 23, 3306, 8080]))}")
    # planted brute force: one IP hammering root over 8 minutes
    t2 = pd.Timestamp("2026-10-21 13:40")
    for i in range(26):
        t2 += pd.Timedelta(seconds=int(rng.integers(8, 25)))
        lines.append(f"{t2.strftime(f'{day} %H:%M:%S')} server sshd[811]: Failed password for root from 185.220.101.4 port 6{1000+i} ssh2")
    # planted spray: one IP, many usernames, slow
    t3 = pd.Timestamp("2026-10-21 15:10")
    for i, user in enumerate(["admin", "root", "oracle", "mysql", "postgres", "test", "guest", "user"]):
        t3 += pd.Timedelta(seconds=int(rng.integers(90, 150)))
        lines.append(f"{t3.strftime(f'{day} %H:%M:%S')} server sshd[811]: Failed password for invalid user {user} from 91.121.87.10 port 4{2000+i} ssh2")
    rng.shuffle(lines)
    return "\n".join(lines) + "\n"
