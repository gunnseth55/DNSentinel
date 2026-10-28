"""Read-only M1 results in the existing Streamlit dashboard."""
import json

import pandas as pd
import streamlit as st


def load_m1_data(connection):
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"m1_predictions", "m1_runtime"} <= tables:
        return pd.DataFrame(), None, {"predictions": 0, "anomalies": 0}
    rows = pd.read_sql_query("SELECT * FROM m1_predictions ORDER BY id DESC LIMIT 200", connection)
    runtime = connection.execute("SELECT timestamp, status, details_json FROM m1_runtime WHERE id=1").fetchone()
    total, anomalies = connection.execute(
        "SELECT COUNT(*), COALESCE(SUM(anomaly),0) FROM m1_predictions").fetchone()
    return rows, runtime, {"predictions": total, "anomalies": anomalies}


def render_m1(rows, runtime, counts):
    st.subheader("M1 GRU autoencoder · shadow mode")
    st.caption("Reconstruction error measures deviation from the benign training reference. "
               "It is not an attack probability. M1 never blocks DNS requests.")
    if runtime is None:
        st.info("M1 has not started. Restart dns_server.py to enable shadow inference.")
        return
    updated, status, raw = runtime
    details = json.loads(raw)
    st.write(f"**Worker:** {status} · Last update: {updated}")
    if details.get("last_error"):
        st.warning(f"M1: {details['last_error']}. DNS forwarding remains independent.")
    st.caption(f"Model: {details.get('model_version', 'loading')} | "
               f"Grouping: {details.get('group_by', 'checkpoint-defined')} | "
               f"Window: {details.get('sequence_length', '?')} queries | "
               f"Threshold: {details.get('threshold', 'loading')}")
    st.caption("Windows do not overlap. The saved model uses query-only features; "
               "missing DNS responses do not become fabricated input values. "
               "Partial windows wait for 20 queries and expire after a 300-second idle gap.")
    if details.get("dropped_observations") or details.get("errors"):
        st.warning(f"Dropped observations: {details.get('dropped_observations', 0)}; "
                   f"processing errors: {details.get('errors', 0)}. Interrupted windows are discarded.")
    a, b = st.columns(2)
    a.metric("M1 evaluated sequences", counts["predictions"])
    b.metric("M1 anomalous sequences", counts["anomalies"])
    progress = details.get("progress", [])
    if progress:
        st.write("**Current sequence warm-up (most recent clients)**")
        st.dataframe(pd.DataFrame(progress), hide_index=True, width="stretch")
    if rows.empty:
        st.info("No M1 predictions yet. Send 20 queries from one client within the idle limit.")
        return
    display = rows.copy()
    display["decision"] = display["anomaly"].map({0: "NORMAL", 1: "ANOMALY"})
    for column in ("domains_json", "parent_domains_json", "distribution_warnings_json"):
        display[column.removesuffix("_json")] = display[column].map(lambda v: "; ".join(json.loads(v)))
    st.dataframe(display[["timestamp", "client_ip", "parent_domains", "reconstruction_error",
                          "threshold", "decision", "sequence_size", "model_version",
                          "distribution_warnings", "domains"]], hide_index=True, width="stretch")
    latest = rows.iloc[0]
    warnings = json.loads(latest["distribution_warnings_json"])
    if warnings:
        st.warning("Latest window differs from training: " + " ".join(warnings))
    st.caption("Recent results include previous gateway sessions. A NORMAL decision does not prove safety, "
               "and an ANOMALY decision does not prove exfiltration. The threshold was fitted on benign "
               "training errors; attack detection accuracy has not been established.")
