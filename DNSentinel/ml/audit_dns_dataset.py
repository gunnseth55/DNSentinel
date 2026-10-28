"""Audit existing CSVs against raw PCAPs/TShark without replacing any extraction."""
import argparse
import csv
import json
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from ml.common import read_json, sha256, write_json


SOURCE = "https://www.unb.ca/cic/datasets/dns-exf-2021.html"
TS_FIELDS = ["frame.number", "frame.cap_len", "frame.len", "frame.time_epoch",
             "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
             "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.response_to",
             "dns.flags.rcode"]


def tshark_audit(executable, path, csv_rows):
    command = [str(executable), "-n", "-2", "-r", str(path), "-Y", "dns || tcp.port == 53",
               "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for field in TS_FIELDS:
        command += ["-e", field]
    counts, named_queries, referenced_queries = Counter(), set(), set()
    disagreements = 0
    # Do not let stderr fill a pipe while stdout is consumed. Check the exit code.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, encoding="utf-8", errors="replace")
    try:
        for line in process.stdout:
            values = line.rstrip("\r\n").split("\t")
            values += [""] * (len(TS_FIELDS) - len(values))
            row = dict(zip(TS_FIELDS, values))
            if row["tcp.srcport"] or row["tcp.dstport"]:
                counts["tcp_port53_packets"] += 1
            flag = row["dns.flags.response"]
            if flag not in ("0", "1", "False", "True"):
                continue
            counts["dns_packets"] += 1
            if row["udp.srcport"] != "53" and row["udp.dstport"] != "53":
                counts["dns_recognized_outside_udp53"] += 1
            is_response = flag in ("1", "True")
            counts["dns_responses" if is_response else "dns_queries"] += 1
            complete = bool(row["dns.qry.name"] and row["dns.qry.type"])
            if not is_response:
                counts["queries_with_name_and_type"] += int(complete)
                counts["queries_without_name_or_type"] += int(not complete)
                if complete:
                    named_queries.add(int(row["frame.number"]))
                counts["queries_capture_truncated"] += int(int(row["frame.cap_len"]) < int(row["frame.len"]))
            elif row["dns.response_to"]:
                counts["responses_with_response_to"] += 1
                query_index = int(row["dns.response_to"])
                referenced_queries.add(query_index)
                original = csv_rows.get(query_index)
                if original and original["response_code_numeric"] and row["dns.flags.rcode"]:
                    disagreements += int(original["response_code_numeric"] != row["dns.flags.rcode"])
            if is_response:
                counts["responses_with_name_and_type"] += int(complete)
                counts["responses_capture_truncated"] += int(int(row["frame.cap_len"]) < int(row["frame.len"]))
        if process.wait() != 0:
            raise RuntimeError(f"TShark failed while reading {path}; command: {command}")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait()
    python_matched = {index for index, row in csv_rows.items() if row["response_code"]}
    return {
        "command": command, "counts": dict(counts),
        "distinct_queries_referenced_by_tshark": len(referenced_queries),
        "python_matched_query_rows": len(python_matched),
        "both_reference_same_query_frame": len(python_matched & referenced_queries),
        "python_matched_but_not_tshark_referenced": len(python_matched - referenced_queries),
        "python_only_matches_with_truncated_response": sum(
            csv_rows[index]["response_capture_truncated"].lower() == "true"
            for index in python_matched - referenced_queries),
        "python_only_matches_with_ambiguous_timing": sum(
            csv_rows[index]["response_timing_ambiguous"].lower() == "true"
            for index in python_matched - referenced_queries),
        "tshark_referenced_but_not_python_matched": len(referenced_queries - python_matched),
        "tshark_complete_queries_missing_from_csv": len(named_queries - set(csv_rows)),
        "response_code_disagreements_on_tshark_referenced_csv_queries": disagreements,
        "interpretation": "Python header/question FIFO matching and TShark dissection/response_to association differ, particularly for duplicate questions and truncated response sections. Counts are not equivalent evidence of complete DNS exchanges. Original response values are unchanged.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/cic_bell_exf_2021/processed/all_captures/dns_observations.csv"))
    parser.add_argument("--extraction-audit", type=Path, default=Path("data/cic_bell_exf_2021/processed/all_captures/extraction_audit.json"))
    parser.add_argument("--output", type=Path, default=Path("models/gru/dataset_audit.json"))
    parser.add_argument("--tshark", type=Path)
    args = parser.parse_args()
    report = read_json(args.extraction_audit)
    rows, groups, checks = defaultdict(dict), Counter(), Counter()
    publisher_domain_candidates = []
    previous = {}
    with args.input.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        columns = reader.fieldnames
        for row in reader:
            capture = row["capture_path"]
            index = int(row["packet_index"])
            if index in rows[capture]:
                raise ValueError("Duplicate capture/packet identity in input CSV")
            rows[capture][index] = row
            groups[row["capture_group"]] += 1
            name = row["qname"].lower().rstrip(".")
            if name == "cicresearch.ca" or name.endswith(".cicresearch.ca"):
                publisher_domain_candidates.append({key: row[key] for key in
                                                    ("capture", "packet_index", "timestamp_utc", "qname")})
            stamp = Decimal(row["timestamp_epoch_s"])
            if not stamp.is_finite():
                raise ValueError("Invalid timestamp")
            key = (capture, row["client_ip"])
            checks["chronological_order_regressions"] += int(key in previous and stamp < previous[key])
            previous[key] = stamp
            iso = Decimal(str(datetime.fromisoformat(row["timestamp_utc"]).timestamp()))
            checks["epoch_iso_disagreements_over_2_microseconds"] += int(abs(stamp - iso) > Decimal("0.000002"))
            checks["missing_responses"] += int(not row["response_code"])
            checks["missing_response_inconsistencies"] += int(bool(row["response_code"]) != bool(row["response_code_numeric"]))
            checks["repeated_outstanding_query_rows"] += int(row["is_repeated_outstanding_query"].lower() == "true")
            checks["ambiguous_response_timing_rows"] += int(row["response_timing_ambiguous"].lower() == "true")
    executable = args.tshark or shutil.which("tshark")
    if not executable and Path("C:/Program Files/Wireshark/tshark.exe").is_file():
        executable = Path("C:/Program Files/Wireshark/tshark.exe")
    captures = []
    for capture in report["captures"]:
        path = Path(capture["capture_path"])
        print(f"Auditing {path.name} ...", flush=True)
        entry = {key: capture.get(key) for key in (
            "capture", "capture_group", "snaplen_bytes", "extracted_observations",
            "capture_start_utc", "capture_end_utc", "counts",
        )}
        entry["source_sha256_matches_extraction"] = path.is_file() and sha256(path) == capture["sha256"]
        entry["csv_rows"] = len(rows[str(path)])
        if executable:
            entry["tshark"] = tshark_audit(executable, path, rows[str(path)])
        else:
            entry["tshark"] = {"status": "not_available", "command_to_install": "Install official Wireshark/TShark, then rerun this audit."}
        captures.append(entry)
    attack = [capture for capture in captures if capture["capture_group"] != "benign"]
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_csv": str(args.input.resolve()), "input_sha256": sha256(args.input),
        "extraction_audit_sha256": sha256(args.extraction_audit), "columns": columns,
        "observations": sum(groups.values()), "source_category_counts_not_labels": dict(groups),
        "checks": dict(checks), "captures": captures,
        "attack_capture_dns_queries": sum(capture["counts"].get("dns_query_packets", 0) for capture in attack),
        "attack_capture_question_failures": sum(capture["counts"].get("incomplete_or_invalid_dns_query_questions", 0) for capture in attack),
        "label_assessment": {
            "supervised_query_labels_ready": False,
            "publisher_source": SOURCE,
            "finding": "Publisher supplies benign capture provenance and attack schedules but no timezone-qualified per-query labels among the local files. Mixed attack captures include background queries. Do not infer labels from folder/file names.",
            "benign_fallback": "Use only the two publisher-designated benign recordings, with one capture for training and one for preliminary validation. This is an operational benign-reference assumption, not independent per-query ground truth.",
            "attack_schedule_caution": "Published local clock schedules cannot be silently mapped to UTC; the first light-image query in this local capture is at 2020-11-22 01:46 UTC, and published session boundaries need explicit validation.",
            "publisher_exfiltration_domain_candidate_rows_not_labels": publisher_domain_candidates,
            "candidate_caution": "Matching the publisher's attack-domain description is supporting evidence, not automatic per-query ground truth; one recovered candidate does not establish representative 20-query attack sequences.",
        },
        "training_recommendation": "Prepare benign-only sequence autoencoder. Exclude response-derived and capture-artifact features by default. Do not train a supervised classifier on the current provenance categories.",
        "extractor_ordering_limitation": "The existing extractor associates responses in packet-file order, then sorts extracted queries. Capture timestamp regressions can therefore cause missed matches. This audit does not silently repair those associations.",
        "limitations": ["Recognized nonstandard-port DNS is counted by TShark; concealed/encrypted DNS and arbitrary protocols are not exhaustively ruled out.",
                        "Full QNAME bytes missing from 96-byte captures cannot be reconstructed.",
                        "No extraction outputs were changed; response matching is not treated as ground truth.",
                        "Two adjacent benign recordings provide only preliminary session-held-out validation, not an independent deployment test."],
    }
    write_json(args.output, summary)
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
