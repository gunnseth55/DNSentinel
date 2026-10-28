import sqlite3
import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st
from p1_dashboard import load_p1_data, render_p1
from m1_dashboard import load_m1_data, render_m1

DB_PATH = Path(os.environ.get("DNSENTINEL_DB_PATH", Path(__file__).resolve().parent / "dns_events.db"))

st.set_page_config(
    page_title="DNSentinel | Security Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.title("DNSentinel")
st.caption("Live DNS activity and explainable security alerts • Read-only dashboard")


@st.fragment(run_every="3s")
def live_dashboard():
    if not DB_PATH.is_file():
        st.warning(
            f"Database not found: {DB_PATH}. "
            "Start dns_server.py in the same folder and send a DNS query."
        )
        return

    connection = None
    try:
        connection = sqlite3.connect(DB_PATH, timeout=5)
        metrics = pd.read_sql_query(
            """
            SELECT
              (SELECT COUNT(*) FROM dns_logs) AS total_queries,
              (SELECT COUNT(*) FROM dns_logs WHERE status = 'BLOCKED') AS blocked,
              (SELECT COUNT(*) FROM dns_alerts WHERE detector = 'BASELINE') AS baseline_alerts,
              (SELECT COUNT(*) FROM dns_alerts WHERE detector = 'BEHAVIOUR') AS behaviour_alerts,
              (SELECT COUNT(*) FROM dns_alerts WHERE detector = 'B1') AS b1_alerts
            """,
            connection,
        ).iloc[0]

        logs = pd.read_sql_query(
            """
            SELECT timestamp, client_ip, domain, query_type,
                   status, response_code
            FROM dns_logs
            ORDER BY id DESC
            LIMIT 500
            """,
            connection,
        )

        alert_columns = {row[1] for row in connection.execute("PRAGMA table_info(dns_alerts)")}
        optional_columns = [name for name in (
            "triggered_rules", "features_json", "rule_details_json",
            "configuration", "last_seen", "occurrences",
        ) if name in alert_columns]
        extras = ", " + ", ".join(optional_columns) if optional_columns else ""
        alerts = pd.read_sql_query(
            f"""
            SELECT id, timestamp, client_ip, domain, detector,
                   risk, score, reasons{extras}
            FROM dns_alerts
            ORDER BY id DESC
            LIMIT 300
            """,
            connection,
        )
        try:
            p1_current, p1_history = load_p1_data(connection)
            p1_error = None
        except (sqlite3.Error, pd.errors.DatabaseError) as exc:
            p1_current, p1_history = pd.DataFrame(), pd.DataFrame()
            p1_error = str(exc)
        try:
            m1_rows, m1_runtime, m1_counts = load_m1_data(connection)
            m1_error = None
        except (sqlite3.Error, pd.errors.DatabaseError, ValueError) as exc:
            m1_rows, m1_runtime = pd.DataFrame(), None
            m1_counts = {"predictions": 0, "anomalies": 0}
            m1_error = str(exc)
    except (sqlite3.Error, ValueError, KeyError) as exc:
        st.error(
            "Could not read the DNSentinel tables. "
            "Check that dns_server.py uses the dns_logs and dns_alerts schema. "
            f"Details: {exc}"
        )
        return
    finally:
        if connection is not None:
            connection.close()

    st.caption("Refreshing every 3 seconds while this page is open")
    cols = st.columns(6)
    cols[0].metric("DNS queries", int(metrics["total_queries"]))
    cols[1].metric("Blocked queries", int(metrics["blocked"]))
    cols[2].metric("Baseline alerts", int(metrics["baseline_alerts"]))
    cols[3].metric("Behaviour alerts", int(metrics["behaviour_alerts"]))
    cols[4].metric("B1 alerts", int(metrics["b1_alerts"]))
    cols[5].metric("M1 anomalies", m1_counts["anomalies"])

    tab_queries, tab_alerts, tab_p1, tab_m1, tab_analytics = st.tabs(
        ["DNS activity", "Security alerts", "P1 monitor", "M1 monitor", "Traffic analysis"]
    )

    with tab_queries:
        st.subheader("Recent DNS requests")
        if logs.empty:
            st.info("No DNS traffic recorded yet. Run a query with dns_client.py.")
        else:
            selected_status = st.selectbox(
                "Filter by server decision",
                ["All"] + sorted(logs["status"].dropna().unique().tolist()),
                key="dns_status_filter",
            )
            visible_logs = (
                logs if selected_status == "All"
                else logs[logs["status"] == selected_status]
            )
            st.dataframe(visible_logs, hide_index=True, width="stretch")
            st.caption("Displaying up to 500 most recent DNS requests.")

    with tab_alerts:
        st.subheader("Detector alerts")
        if alerts.empty:
            st.success("No security alerts recorded yet.")
        else:
            detector_options = ["All", "BASELINE", "BEHAVIOUR", "B1"]
            selected_detector = st.selectbox(
                "Detection engine", detector_options, key="alert_detector_filter"
            )
            visible_alerts = (
                alerts if selected_detector == "All"
                else alerts[alerts["detector"] == selected_detector]
            )
            visible_columns = [name for name in visible_alerts.columns
                               if name not in ("features_json", "rule_details_json")]
            st.dataframe(visible_alerts[visible_columns], hide_index=True, width="stretch")
            b1_rows = visible_alerts[visible_alerts["detector"] == "B1"]
            if not b1_rows.empty and "rule_details_json" in b1_rows:
                with st.expander("B1 measured features and rule explanations"):
                    selected_id = st.selectbox(
                        "B1 incident", b1_rows["id"].tolist(),
                        format_func=lambda value: (
                            f"#{value} | " + b1_rows.set_index("id").loc[value, "client_ip"]
                            + " | " + b1_rows.set_index("id").loc[value, "domain"]
                        ), key="b1_incident",
                    )
                    incident = b1_rows[b1_rows["id"] == selected_id].iloc[0]
                    for column, label in (("features_json", "Latest evaluation features"),
                                          ("rule_details_json", "Last triggering values for each rule")):
                        st.write(f"**{label}**")
                        try:
                            st.json(json.loads(incident[column]))
                        except (TypeError, ValueError):
                            st.info("No structured values recorded for this incident.")
                    st.caption(
                        "B1 merges continuing alerts per client/domain. Rule IDs accumulate "
                        "within an incident; active_rule_ids lists rules active at the latest "
                        "evaluation. B1 uses severity labels and leaves the score empty."
                    )
            st.caption(
                "Scores are fixed rule-based severity indicators, "
                "not probabilities of malicious activity."
            )

    with tab_p1:
        if p1_error:
            st.error(f"Could not read P1 data: {p1_error}")
        else:
            render_p1(p1_current, p1_history)

    with tab_m1:
        if m1_error:
            st.error(f"Could not read M1 data: {m1_error}")
        else:
            render_m1(m1_rows, m1_runtime, m1_counts)

    with tab_analytics:
        st.subheader("Traffic analysis")
        if logs.empty:
            st.info("Charts will appear after DNS requests are logged.")
        else:
            left, right = st.columns(2)
            with left:
                st.write("**Decisions (recent requests)**")
                status_counts = logs["status"].value_counts()
                st.bar_chart(status_counts)
            with right:
                st.write("**Most queried domains (recent requests)**")
                top_domains = logs["domain"].value_counts().head(10)
                st.bar_chart(top_domains)

            st.write("**Alert counts by detector (recent alerts)**")
            if alerts.empty:
                st.info("No alerts available for comparison yet.")
            else:
                st.bar_chart(alerts["detector"].value_counts())
            st.caption(
                "Charts use at most the latest 500 DNS requests and 300 alerts. "
                "Counters at the top use all stored rows. Alert counts alone "
                "do not measure detection accuracy."
            )


live_dashboard()
