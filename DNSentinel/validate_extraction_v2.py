"""Read-only source checks and streaming validation of extraction_v2 outputs.

Writes validation_report.json and extraction_summary.md beside the new outputs;
does not alter observations, original datasets, raw captures or model files.
"""
import argparse
import csv
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from prepare_gru_dataset_v2 import FIELDS, digest, timestamp_ns, write_json


def validate(directory, legacy_dir=None):
    audit = json.loads((directory / "extraction_audit.json").read_text(encoding="utf-8"))
    if audit["status"] != "completed" or audit["schema_version"] != "dns-extraction-v2":
        raise ValueError("The extraction is not a completed v2 run")
    if digest(directory / "dns_observations.csv") != audit["output_csv_sha256"]:
        raise ValueError("Observation CSV no longer matches its audit hash")
    per_capture, scopes, match_methods, response_codes = defaultdict(Counter), Counter(), Counter(), Counter()
    seen, previous_order, source_by_name = set(), None, {}
    row_counts = Counter()
    legacy, legacy_changes, changes_by_capture, change_examples = {}, Counter(), defaultdict(Counter), []
    recovered_associations = []
    query_orders = defaultdict(dict)
    if legacy_dir is not None:
        with (legacy_dir / "dns_observations.csv").open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                legacy[(row["capture_path"], int(row["packet_index"]))] = row["response_code_numeric"]
    captures = {capture["capture_path"]: capture for capture in audit["captures"]}
    with (directory / "dns_observations.csv").open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != FIELDS:
            raise ValueError("CSV schema differs from the declared v2 schema")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("Inconsistent CSV field count")
            capture = captures[row["capture_path"]]
            source_by_name[row["capture"]] = row["capture_path"]
            if row["capture_sha256"] != capture["sha256"] or row["capture_group"] != capture["capture_group"]:
                raise ValueError("Observation capture identity/category mismatch")
            frame, pdu, question = (int(row[name]) for name in ("packet_index", "dns_message_index", "question_index"))
            expected_identity = f"{capture['sha256']}:{frame}:{pdu}:{question}"
            if row["observation_id"] != expected_identity or expected_identity in seen:
                raise ValueError("Invalid or duplicate observation identity")
            seen.add(expected_identity)
            ns = timestamp_ns(row["timestamp_epoch_s"])
            iso_ns = Decimal(str(datetime.fromisoformat(row["timestamp_utc"]).timestamp())) * 1_000_000_000
            if abs(Decimal(ns) - iso_ns) > 2000:
                raise ValueError("UTC/epoch timestamp mismatch")
            ordering = (row["capture_path"], ns, frame, pdu, question)
            if previous_order is not None and ordering < previous_order:
                raise ValueError("CSV is not in declared chronological order")
            previous_order = ordering
            message_identity = (frame, pdu)
            declared_order = int(row["capture_query_order"])
            if message_identity in query_orders[row["capture_path"]] and query_orders[row["capture_path"]][message_identity] != declared_order:
                raise ValueError("Inconsistent original-order provenance across questions")
            query_orders[row["capture_path"]][message_identity] = declared_order
            for field in ("client_ip", "server_ip"):
                ipaddress.ip_address(row[field])
            for field in ("qtype_numeric", "qclass", "dns_transaction_id"):
                if not 0 <= int(row[field]) <= 65535:
                    raise ValueError("Invalid numeric DNS field")
            if not (1 <= question <= int(row["question_count"])):
                raise ValueError("Question ordinal not within the declared question count")
            if int(row["decoded_question_count"]) > int(row["question_count"]):
                raise ValueError("Decoded more questions than declared")
            if not row["qname"] or row["transport"] not in ("udp", "tcp"):
                raise ValueError("Missing domain or unsupported output transport")
            matched = row["response_matched"] == "True"
            if not matched and any(row[field] for field in ("response_code", "response_code_numeric", "response_timestamp_utc", "response_latency_s")):
                raise ValueError("Unmatched observation contains invented response values")
            if row["response_code_numeric"] and not 0 <= int(row["response_code_numeric"]) <= 4095:
                raise ValueError("Invalid header/extended RCODE")
            if row["response_latency_s"] and float(row["response_latency_s"]) < 0:
                raise ValueError("Negative response latency")
            if row["time_since_prev_query_s"] and float(row["time_since_prev_query_s"]) < 0:
                raise ValueError("Negative chronological query gap")
            if row["dns_scope"] == "multicast_dns" and row["response_matched"] != "False":
                raise ValueError("mDNS was forced into an unsupported one-to-one response pairing")
            if bool(row["response_code"]) != bool(row["response_code_numeric"]):
                raise ValueError("Response name/numeric missingness mismatch")
            per_capture[row["capture"]][row["dns_scope"]] += 1
            per_capture[row["capture"]]["matched"] += int(matched)
            per_capture[row["capture"]]["repeated_candidate"] += row["is_repeated_outstanding_query"] == "True"
            per_capture[row["capture"]]["tshark_retransmission"] += row["tshark_retransmission"] == "True"
            row_counts[row["capture"]] += 1
            scopes[row["dns_scope"]] += 1
            match_methods[row["response_match_method"] or "unmatched"] += 1
            response_codes[row["response_code"] or "UNKNOWN"] += 1
            if row["dns_scope"] == "unicast_dns" and question == 1 and legacy_dir is not None:
                key = (row["capture_path"], frame)
                if key not in legacy:
                    category = "new_query_not_in_legacy"
                else:
                    previous_code, current_code = legacy[key], row["response_code_numeric"]
                    if previous_code == current_code:
                        category = "same_response_code_or_same_missingness"
                    elif previous_code and not current_code:
                        category = "old_assigned_now_explicitly_unmatched"
                    elif not previous_code and current_code:
                        category = "old_unmatched_now_associated"
                    else:
                        category = "associated_response_code_changed"
                    if category != "same_response_code_or_same_missingness" and len(change_examples) < 12:
                        change_examples.append({"capture": row["capture"], "frame": frame,
                                                "old_rcode": previous_code, "new_rcode": current_code,
                                                "new_match_status": row["match_status"]})
                    if category == "old_unmatched_now_associated" and len(recovered_associations) < 12:
                        recovered_associations.append({key: row[key] for key in (
                            "capture", "packet_index", "response_packet_index", "response_match_method",
                            "timestamp_epoch_s", "response_timestamp_utc")})
                legacy_changes[category] += 1
                changes_by_capture[row["capture"]][category] += 1
    groups = defaultdict(Counter)
    capture_results = []
    for capture in audit["captures"]:
        name, counts = capture["capture"], capture["dns_counts"]
        actual = per_capture[name]
        file_order = query_orders[capture["capture_path"]]
        if [file_order[key] for key in sorted(file_order)] != list(range(1, len(file_order) + 1)):
            raise ValueError(f"Original frame/PDU ordering provenance is inconsistent: {name}")
        if row_counts[name] != capture["output_counts"].get("observations", 0):
            raise ValueError(f"CSV/audit observation count mismatch: {name}")
        # Account for every decoded question as exported or explicitly unsupported.
        decoded = counts.get("dns_decoded_query_questions", 0) + counts.get("mdns_decoded_query_questions", 0)
        unsupported = sum(value for reason, value in capture["exclusion_reasons"].items()
                          if reason.endswith(("unsupported_opcode_query_questions", "unsupported_transport_query_questions"))
                          or reason == "mdns_explicitly_excluded_query_questions")
        if decoded != row_counts[name] + unsupported:
            raise ValueError(f"Decoded-question accounting discrepancy: {name}")
        if not all(capture["validation"].values()):
            raise ValueError(f"An extractor validation failed: {name}")
        group = groups[capture["capture_group"]]
        group["ordinary_dns"] += actual["unicast_dns"]
        group["mdns"] += actual["multicast_dns"]
        group["total"] += row_counts[name]
        capture_results.append({"capture": name, "rows": row_counts[name], "scopes": dict(actual),
                                "tshark_decoded_query_questions": decoded, "explicitly_unsupported_decoded_questions": unsupported,
                                "additional_nonstandard_udp_candidates": capture["possible_nonstandard_dns_candidates"]})
    preservation = json.loads((directory / "preservation_manifest.json").read_text(encoding="utf-8"))
    if preservation["status"] != "verified_unchanged":
        raise ValueError("Protected input preservation was not verified")
    for filename, expected in preservation["before_sha256"].items():
        if digest(filename) != expected:
            raise ValueError(f"Protected input changed: {filename}")
    result = {
        "status": "passed", "rows": sum(row_counts.values()), "unique_observation_ids": len(seen),
        "groups": {name: dict(value) for name, value in groups.items()},
        "scopes": dict(scopes), "response_match_methods": dict(match_methods),
        "response_codes": dict(response_codes), "captures": capture_results,
        "legacy_response_comparison": dict(legacy_changes),
        "legacy_response_comparison_by_capture": {name: dict(value) for name, value in changes_by_capture.items()},
        "legacy_response_change_examples": change_examples,
        "recovered_association_examples": recovered_associations,
        "checks": ["source and model SHA-256 preservation", "CSV hash and schema", "capture identity",
                   "composite observation identity uniqueness", "chronological order", "DNS/IP numeric field ranges",
                   "question ordinal/count alignment", "no fabricated unmatched response values",
                   "nonnegative latency and gaps", "mDNS separation", "TShark decoded-question accounting",
                   "original query ordering provenance", "UTC/epoch timestamp consistency", "legacy response change accounting"],
        "readiness": "Ready for separate provenance/scope and label review, not automatic GRU training. Most ordinary attack questions remain missing; labels are not inferred.",
    }
    write_json(directory / "validation_report.json", result)
    with (directory / "extraction_comparison.csv").open(newline="", encoding="utf-8") as stream:
        comparison = list(csv.DictReader(stream))
    lines = ["# Extraction v2: actual results", "", "New rows are individual decoded questions; ordinary DNS and mDNS remain separate scopes.", "",
             "| Capture | Old questions | New questions | Ordinary DNS | mDNS | DNS responses | Still excluded ordinary questions |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for row in comparison:
        lines.append("| " + " | ".join(row[key] for key in ("capture", "old_queries", "new_queries", "new_unicast_dns_questions", "new_mdns_questions", "dns_responses", "still_excluded")) + " |")
    lines += ["", "All increases above the ordinary-DNS counts are explicitly tagged multicast DNS, not newly recovered attack payloads.",
              "The still-excluded column counts ordinary-DNS question exclusions; multicast exclusions and other protocols are detailed in the JSON audit.",
              "", "## Validation", "", f"{result['rows']:,} rows validated with {result['unique_observation_ids']:,} unique observation IDs. Protected source/data/model hashes are unchanged.",
              "", "Do not use source-capture category as a class label. The legacy GRU builder's capture/frame uniqueness check needs a separately reviewed composite-key adapter before consuming multi-question or multi-PDU rows."]
    (directory / "extraction_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent / "data/cic_bell_exf_2021/processed/extraction_v2")
    parser.add_argument("--legacy-dir", type=Path, default=Path(__file__).resolve().parent / "data/cic_bell_exf_2021/processed/all_captures")
    args = parser.parse_args()
    try:
        report = validate(args.directory, args.legacy_dir)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f"Validation failed: {error}\n")
    print(json.dumps({key: report[key] for key in ("status", "rows", "groups", "scopes", "response_match_methods")}, indent=2))


if __name__ == "__main__":
    main()
