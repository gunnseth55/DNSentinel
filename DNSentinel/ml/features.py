"""Identical, causal feature calculation for offline sequences and shadow inference."""
import math
from decimal import Decimal

import numpy as np

from p1_detector import EXTRACT, entropy


SCHEMA_VERSION = "m1-features-v1"
QUERY_FEATURES = [
    "leftmost_label_length", "qname_length", "leftmost_label_entropy",
    "leftmost_digit_ratio", "subdomain_label_count", "log1p_query_gap_s",
    "qtype_A", "qtype_AAAA", "qtype_TXT", "qtype_NULL", "qtype_private", "qtype_other",
]
RESPONSE_FEATURES = [
    "explicit_response_observed", "rcode_NOERROR", "rcode_NXDOMAIN",
    "rcode_SERVFAIL", "rcode_REFUSED", "rcode_other",
]


def truth(value):
    return value is True or str(value).lower() in ("true", "1")


def timestamp(row):
    value = row.get("timestamp_monotonic_s", row.get("timestamp_epoch_s"))
    if value is None or value == "":
        raise ValueError("Each observation needs timestamp_epoch_s or timestamp_monotonic_s")
    result = Decimal(str(value))
    if not result.is_finite():
        raise ValueError("Timestamp is not finite")
    return result


def parent_domain(row):
    parts = EXTRACT(row["qname"].lower().rstrip("."))
    return f"{parts.domain}.{parts.suffix}" if parts.domain and parts.suffix else ""


def feature_schema(sequence_length=20, min_length=20, group_by="client", max_gap_s=300,
                   include_responses=False):
    return {
        "schema_version": SCHEMA_VERSION,
        "feature_names": QUERY_FEATURES + (RESPONSE_FEATURES if include_responses else []),
        "sequence_length": sequence_length, "min_length": min_length,
        "group_by": group_by, "max_gap_s": max_gap_s,
        "include_responses": include_responses,
        "gap_semantics": "Within-sequence chronological query gap; first query is zero; log1p transform.",
        "response_semantics": "Optional: exact verified question match or explicit live matched response only; unknown stays unobserved.",
        "qtype_encoding": "Fixed one-hot A/AAAA/TXT/NULL/private-use 65280-65534/other; never ordinal.",
        "excluded_inputs": ["capture", "capture_group", "capture_path", "absolute timestamps",
                            "client_ip", "server_ip", "session_id", "labels", "capture_truncated",
                            "retransmission flags", "response latency", "domain string/identity"],
    }


def feature_vector(row, gap_s, include_responses=False):
    name = row["qname"].lower().rstrip(".")
    if not name or any(not label for label in name.split(".")):
        raise ValueError("QNAME must be complete and nonempty")
    label = name.split(".")[0]
    qtype = int(row["qtype_numeric"])
    if not 0 <= qtype <= 65535 or not math.isfinite(gap_s) or gap_s < 0:
        raise ValueError("Invalid numeric DNS type or chronological gap")
    parts = EXTRACT(name)
    category = {1: 0, 28: 1, 16: 2, 10: 3}.get(qtype, 4 if 65280 <= qtype <= 65534 else 5)
    values = [len(label), len(name), entropy(label),
              sum("0" <= char <= "9" for char in label) / len(label),
              len(parts.subdomain.split(".")) if parts.subdomain else 0,
              math.log1p(gap_s)] + [int(category == i) for i in range(6)]
    if include_responses:
        verified = (truth(row.get("response_matched", False)) or
                    (row.get("match_status") == "question_verified" and
                     truth(row.get("response_question_verified", False))))
        verified = verified and row.get("response_code_numeric", "") != ""
        verified = verified and not truth(row.get("response_timing_ambiguous", False))
        code = int(row["response_code_numeric"]) if verified else None
        if code is not None and not 0 <= code <= 15:
            raise ValueError("Only header DNS response codes 0-15 are supported")
        values += [int(verified)] + [int(verified and code == item) for item in (0, 3, 2, 5)]
        values += [int(verified and code not in (0, 3, 2, 5))]
    result = np.asarray(values, dtype=np.float32)
    if not np.isfinite(result).all():
        raise ValueError("Nonfinite feature value")
    return result


def sequence_features(observations, schema):
    previous = None
    result = []
    for row in observations:
        current = timestamp(row)
        gap = float(current - previous) if previous is not None else 0.0
        if gap < 0 or gap > schema["max_gap_s"]:
            raise ValueError("Sequence is out of order or crosses the configured idle/session gap")
        result.append(feature_vector(row, gap, schema["include_responses"]))
        previous = current
    return np.stack(result)
