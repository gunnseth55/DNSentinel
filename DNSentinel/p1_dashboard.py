"""Read-only P1 dashboard views backed by server evaluation snapshots."""

import json

import pandas as pd
import streamlit as st


FEATURE_LABELS = {
    "query_count": "Queries in 60 seconds",
    "unique_subdomains": "Unique subdomains",
    "unique_ratio": "Unique subdomain ratio",
    "max_label_length": "Longest label (characters)",
    "max_label_entropy": "Highest label entropy (bits/character)",
    "queries_last_15s": "Queries in 15 seconds",
    "nxdomain_count": "NXDOMAIN responses",
    "nxdomain_ratio": "NXDOMAIN ratio",
}


def load_p1_data(connection):
    tables = {
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    current = pd.DataFrame()
    history = pd.DataFrame()
    if "p1_current" in tables:
        current = pd.read_sql_query(
            "SELECT * FROM p1_current ORDER BY client_ip, parent_domain", connection
        )
    if "p1_transitions" in tables:
        history = pd.read_sql_query(
            "SELECT * FROM p1_transitions ORDER BY id DESC LIMIT 300", connection
        )
    return current, history


def decode_json(value, expected_type):
    try:
        result = json.loads(value)
        return result if isinstance(result, expected_type) else expected_type()
    except (TypeError, ValueError):
        return expected_type()


def show_evidence(row):
    evidence = decode_json(row["evidence_json"], dict)
    for col, family in zip(st.columns(3), ("naming", "timing", "response")):
        col.metric(
            f"{family.title()} evidence",
            "Present" if evidence.get(family) is True
            else "Absent" if evidence.get(family) is False else "Unavailable",
        )
    features = decode_json(row["features_json"], dict)
    values = []
    for name, label in FEATURE_LABELS.items():
        value = features.get(name)
        if isinstance(value, (int, float)) and name.endswith("ratio"):
            value = f"{value:.1%}"
        values.append({"Feature": label, "Value": str(value) if value is not None else "Unavailable"})
    st.dataframe(pd.DataFrame(values), hide_index=True, width="stretch")


def show_samples(row):
    samples = [
        sample for sample in decode_json(row["samples_json"], list)
        if isinstance(sample, dict)
    ]
    if samples:
        st.dataframe(pd.DataFrame(samples), hide_index=True, width="stretch")
        st.caption("Up to five most recent contributing queries saved at this evaluation.")
    else:
        st.info("No query samples in this evaluation window.")


def render_p1(current, history):
    st.subheader("P1 security monitor")
    st.caption(
        "A 60-second observation window is evaluated about every 5 seconds. "
        "Naming evidence creates WATCH; naming plus timing or response evidence creates ALERT."
    )
    available = [frame for frame in (current, history) if not frame.empty]
    if not available:
        st.info(
            "No P1 data yet. Restart dns_server.py after this update, then query "
            "subdomains such as one.demo.test. P1 monitors eligible subdomain queries."
        )
        return

    clients = sorted(set().union(*(set(frame["client_ip"]) for frame in available)))
    client = st.selectbox("P1 client", ["All"] + clients, key="p1_client")
    if client != "All":
        current = current[current["client_ip"] == client] if not current.empty else current
        history = history[history["client_ip"] == client] if not history.empty else history
    available = [frame for frame in (current, history) if not frame.empty]
    parents = sorted(set().union(*(set(frame["parent_domain"]) for frame in available)))
    parent = st.selectbox("P1 parent domain", ["All"] + parents, key="p1_parent")
    if parent != "All":
        current = current[current["parent_domain"] == parent] if not current.empty else current
        history = history[history["parent_domain"] == parent] if not history.empty else history

    st.write("**Current P1 states**")
    if current.empty:
        st.info(
            "No current evaluation snapshots for this selection. Restart the updated "
            "DNS server and send eligible queries; saved history remains available below."
        )
    else:
        for col, state in zip(st.columns(3), ("NORMAL", "WATCH", "ALERT")):
            col.metric(f"{state} pairs", int((current["state"] == state).sum()))
        view = current[["client_ip", "parent_domain", "state", "timestamp"]].copy()
        for family in ("naming", "timing", "response"):
            view[family + "_evidence"] = current["evidence_json"].map(
                lambda value: decode_json(value, dict).get(family)
            )
        st.dataframe(view, hide_index=True, width="stretch")
        st.caption(
            "States and values reflect each pair's last server evaluation; timestamps are UTC. "
            "A stopped server cannot refresh them. Expired pairs retain their final NORMAL "
            "snapshot until the server restarts. NORMAL means no P1 rule triggered."
        )
        pairs = list(zip(current["client_ip"], current["parent_domain"]))
        selected = st.selectbox(
            "Inspect current client / domain", pairs,
            format_func=lambda pair: f"{pair[0]} / {pair[1]}", key="p1_pair",
        )
        row = current[
            (current["client_ip"] == selected[0]) & (current["parent_domain"] == selected[1])
        ].iloc[0]
        st.write(f"**{row['state']}** — last evaluated {row['timestamp']}")
        show_evidence(row)
        with st.expander("Queries in the current evaluation"):
            show_samples(row)

    st.write("**State transition history**")
    if history.empty:
        st.info("No state changes recorded for this selection.")
        return
    view = history[["timestamp", "client_ip", "parent_domain"]].copy()
    view["transition"] = history["from_state"] + " → " + history["to_state"]
    st.dataframe(view, hide_index=True, width="stretch")
    st.caption("Latest 300 transitions across all pairs, newest first; filters apply to these rows.")
    labels = {
        row["id"]: (
            f"#{row['id']} · {row['timestamp']} · {row['client_ip']} / "
            f"{row['parent_domain']} · {row['from_state']} → {row['to_state']}"
        ) for _, row in history.iterrows()
    }
    event_id = st.selectbox(
        "Inspect a state change", list(labels), format_func=labels.get, key="p1_transition"
    )
    event = history[history["id"] == event_id].iloc[0]
    st.write(f"**{event['from_state']} → {event['to_state']}**")
    show_evidence(event)
    st.write("**Query samples that contributed to this state change**")
    show_samples(event)
