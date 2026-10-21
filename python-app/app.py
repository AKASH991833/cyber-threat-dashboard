"""Cyber Threat Dashboard - Streamlit UI over threats.py."""
import io

import streamlit as st

from threats import build_report, load_events, sample_log

st.set_page_config(page_title="Cyber Threat Dashboard", page_icon=":shield:", layout="wide")

st.title("Cyber Threat Dashboard")
st.caption("Parse server logs, detect brute force and password spraying, rank attacking IPs. Nothing leaves this app.")

with st.sidebar:
    st.header("Data")
    source = st.radio("Source", ["Sample syslog", "Upload log/CSV"], index=0)
    st.markdown(
        "**Formats:** syslog text (sshd/ufw lines) or CSV with "
        "`ts, source_ip, kind, severity` (optional `user`)."
    )

if source == "Upload log/CSV":
    upload = st.file_uploader("Log file", type=["log", "txt", "csv"])
    if upload is None:
        st.info("Upload a log file to begin, or switch to the sample in the sidebar.")
        st.stop()
    try:
        events = load_events(io.BytesIO(upload.read()))
    except ValueError as exc:
        st.error(str(exc))
        st.stop()
else:
    events = load_events(sample_log())

rep = build_report(events)
k = rep.kpis

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Events", k["events"])
c2.metric("Unique IPs", k["unique_ips"])
c3.metric("Failed logins", k["failed_logins"])
c4.metric("Alerts", k["alerts"])
c5.metric("Critical", k["critical"])

st.subheader("Detected incidents")
if rep.alerts.empty:
    st.success("No incidents detected.")
else:
    def sev_color(row):
        color = {"critical": "#f8d7da", "high": "#fde2cf", "medium": "#fff3cd"}.get(row["severity"], "")
        return [f"background-color: {color}"] * len(row)
    st.dataframe(rep.alerts.style.apply(sev_color, axis=1), use_container_width=True, hide_index=True)

left, right = st.columns(2)
with left:
    st.subheader("Event timeline (hourly)")
    tl = rep.timeline.set_index("hour")
    st.area_chart(tl)
with right:
    st.subheader("Top source IPs")
    st.dataframe(
        rep.top_ips.format({"first_seen": lambda d: d.strftime("%H:%M"), "last_seen": lambda d: d.strftime("%H:%M")}),
        use_container_width=True, hide_index=True,
    )

st.subheader("Events by kind")
st.bar_chart(rep.by_kind.set_index("kind")[["count"]])

with st.expander("Raw events"):
    st.dataframe(rep.events.sort_values("ts", ascending=False), use_container_width=True, height=320)

st.caption(
    "Honest limits: detection is threshold-based heuristics, not a SIEM - tune thresholds for your baseline. "
    "No IP geolocation (no external calls); private vs public ranges only."
)
