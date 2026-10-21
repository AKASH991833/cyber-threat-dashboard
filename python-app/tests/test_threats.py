"""Unit tests for threats.py - run: python3 tests/test_threats.py (or pytest)."""
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threats import build_report, load_events, parse_syslog, sample_log  # noqa: E402

SAMPLE_SYSLOG = """Oct 21 10:00:01 server sshd[811]: Accepted publickey for akash from 10.0.1.5 port 51022 ssh2
Oct 21 10:01:01 server sshd[811]: Failed password for root from 185.1.1.1 port 61000 ssh2
Oct 21 10:01:20 server sshd[811]: Failed password for invalid user oracle from 91.2.2.2 port 41000 ssh2
Oct 21 10:02:00 server kernel: [UFW BLOCK] IN=eth0 SRC=45.3.3.3 DPT=3306
Oct 21 10:02:30 server cron[100]: unrelated noise line
"""


def test_syslog_parsing():
    df = parse_syslog(SAMPLE_SYSLOG)
    assert len(df) == 4, "noise line must be skipped"
    kinds = set(df["kind"])
    assert kinds == {"ssh_login", "ssh_failed", "firewall_block"}
    # "Failed password for invalid user X" is still a failed login, user extracted
    inv = df[df["source_ip"] == "91.2.2.2"].iloc[0]
    assert inv["user"] == "oracle" and inv["kind"] == "ssh_failed"
    fail = df[df["kind"] == "ssh_failed"].iloc[0]
    assert fail["source_ip"] == "185.1.1.1" and fail["user"] == "root"


def test_csv_loading():
    csv = "ts,source_ip,kind,severity,user\n2026-10-21 10:00,1.2.3.4,ssh_failed,medium,root\n2026-10-21 10:01,1.2.3.4,ssh_failed,medium,root\n"
    df = load_events(io.StringIO(csv))
    assert len(df) == 2 and df["source_ip"].iloc[0] == "1.2.3.4"


def test_planted_attacks_detected():
    rep = build_report(load_events(sample_log()))
    kinds = set(rep.alerts["kind"])
    assert "brute_force" in kinds and "password_spray" in kinds
    bf = rep.alerts[rep.alerts["kind"] == "brute_force"].iloc[0]
    assert bf["source_ip"] == "185.220.101.4"
    assert bf["severity"] == "critical"
    spray = rep.alerts[rep.alerts["kind"] == "password_spray"].iloc[0]
    assert spray["users_targeted"] >= 6


def test_clean_log_no_alerts():
    lines = []
    for i in range(20):
        lines.append(f"Oct 21 09:{i:02d}:00 server sshd[811]: Accepted publickey for akash from 10.0.1.{i+2} port 51022 ssh2")
    rep = build_report(parse_syslog("\n".join(lines)))
    assert rep.alerts.empty


def test_kpis_and_aggregation():
    rep = build_report(load_events(sample_log()))
    assert rep.kpis["events"] > 400
    assert rep.kpis["alerts"] >= 2
    assert rep.by_kind["count"].sum() == rep.kpis["events"]
    assert not rep.timeline.empty and not rep.top_ips.empty


def test_unparseable_raises():
    try:
        parse_syslog("nothing useful here\nor here\n")
        assert False, "should raise"
    except ValueError as exc:
        assert "No recognizable" in str(exc)


if __name__ == "__main__":
    for name, fn in sorted({k: v for k, v in globals().items() if k.startswith("test_")}.items()):
        fn()
        print(f"PASS {name}")
    print("ALL PASS")
