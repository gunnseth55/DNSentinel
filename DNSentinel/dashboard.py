import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DB_PATH = Path(__file__).resolve().parent / "dns_events.db"

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
              (SELECT COUNT(*) FROM dns_alerts WHERE detector = 'BEHAVIOUR') AS behaviour_alerts
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

        alerts = pd.read_sql_query(
            """
            SELECT timestamp, client_ip, domain, detector,
                   risk, score, reasons
            FROM dns_alerts
            ORDER BY id DESC
            LIMIT 300
            """,
            connection,
        )
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
    cols = st.columns(4)
    cols[0].metric("DNS queries", int(metrics["total_queries"]))
    cols[1].metric("Blocked queries", int(metrics["blocked"]))
    cols[2].metric("Baseline alerts", int(metrics["baseline_alerts"]))
    cols[3].metric("Behaviour alerts", int(metrics["behaviour_alerts"]))

    tab_queries, tab_alerts, tab_analytics = st.tabs(
        ["DNS activity",  "Security alerts", "Traffic analysis"]
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
            detector_options = ["All", "BASELINE", "BEHAVIOUR"]
            selected_detector = st.selectbox(
                "Detection engine", detector_options, key="alert_detector_filter"
            )
            visible_alerts = (
                alerts if selected_detector == "All"
                else alerts[alerts["detector"] == selected_detector]
            )
            st.dataframe(visible_alerts, hide_index=True, width="stretch")
            st.caption(
                "Scores are fixed rule-based severity indicators, "
                "not probabilities of malicious activity."
            )

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
