"""Extract chronological DNS observations and a provenance/matching audit.

Reads classic Ethernet PCAP (microsecond or nanosecond precision), IPv4/IPv6,
and UDP port 53. DNS-over-TCP/reassembly and training labels are deliberately
outside this extraction step. Requires only the project's existing dnslib and
tldextract dependencies. capture_group describes the source folder, not truth.
"""

import argparse
import csv
import hashlib
import json
import socket
import struct
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

from dnslib import DNSBuffer, DNSHeader, DNSQuestion, DNSError, QTYPE, RCODE
from p1_detector import EXTRACT, entropy


FIELDS = [
    "capture", "capture_path", "capture_group", "packet_index",
    "timestamp_utc", "timestamp_epoch_s", "client_ip", "client_port",
    "server_ip", "server_port", "qname", "qtype", "qtype_numeric", "qclass",
    "registered_domain", "qname_length", "leftmost_label_length",
    "leftmost_label_entropy", "subdomain_label_count", "time_since_prev_query_s",
    "response_code", "response_code_numeric", "response_timestamp_utc",
    "response_latency_s", "match_status", "response_question_verified",
    "is_repeated_outstanding_query", "response_timing_ambiguous",
    "query_capture_truncated", "response_capture_truncated",
]


def utc(timestamp_ns):
    return datetime.fromtimestamp(timestamp_ns / 1_000_000_000, timezone.utc).isoformat(timespec="microseconds")


def read_pcap(path, metadata):
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
        b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1),
    }
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError(f"{path}: requires classic PCAP; PCAPNG is not supported")
        endian, multiplier = formats[header[:4]]
        _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", header)
        if (major, minor) != (2, 4) or linktype != 1:
            raise ValueError(f"{path}: requires PCAP 2.4 Ethernet (link type 1), got {major}.{minor}/{linktype}")
        metadata.update(snaplen_bytes=snaplen, link_type=linktype,
                        timestamp_resolution="microseconds" if multiplier == 1000 else "nanoseconds")
        index = 0
        while True:
            packet_header = stream.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError(f"{path}: incomplete PCAP packet header")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", packet_header)
            if captured > snaplen or captured > 16_777_216 or captured > original:
                raise ValueError(f"{path}: invalid captured packet length")
            if fraction >= (1_000_000 if multiplier == 1000 else 1_000_000_000):
                raise ValueError(f"{path}: invalid packet timestamp fraction")
            data = stream.read(captured)
            if len(data) != captured:
                raise ValueError(f"{path}: incomplete PCAP packet data")
            index += 1
            yield index, seconds * 1_000_000_000 + fraction * multiplier, data, captured < original


def udp_dns(frame, counts):
    if len(frame) < 14:
        counts["incomplete_ethernet_headers"] += 1
        return None
    protocol = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while protocol in (0x8100, 0x88A8, 0x9100):
        if len(frame) < offset + 4:
            counts["incomplete_vlan_headers"] += 1
            return None
        protocol = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    ip = frame[offset:]
    if protocol == 0x0800:
        counts["ipv4_packets"] += 1
        if len(ip) < 20 or ip[0] >> 4 != 4:
            counts["incomplete_or_invalid_ip_headers"] += 1
            return None
        size = (ip[0] & 15) * 4
        total_length = struct.unpack_from("!H", ip, 2)[0]
        if size < 20 or len(ip) < size or total_length < size:
            counts["incomplete_or_invalid_ip_headers"] += 1
            return None
        if struct.unpack_from("!H", ip, 6)[0] & 0x3FFF:
            counts["fragmented_ip_packets_skipped"] += 1
            return None
        source, destination = socket.inet_ntop(socket.AF_INET, ip[12:16]), socket.inet_ntop(socket.AF_INET, ip[16:20])
        transport = ip[9]
        data = ip[size:total_length]
    elif protocol == 0x86DD:
        counts["ipv6_packets"] += 1
        if len(ip) < 40 or ip[0] >> 4 != 6:
            counts["incomplete_or_invalid_ip_headers"] += 1
            return None
        source, destination = socket.inet_ntop(socket.AF_INET6, ip[8:24]), socket.inet_ntop(socket.AF_INET6, ip[24:40])
        transport = ip[6]
        data = ip[40:40 + struct.unpack_from("!H", ip, 4)[0]]
        while transport in (0, 43, 44, 51, 60):
            if len(data) < 8:
                counts["incomplete_ipv6_extension_headers"] += 1
                return None
            next_header = data[0]
            if transport == 44:
                if struct.unpack_from("!H", data, 2)[0] & 0xFFF9:
                    counts["fragmented_ip_packets_skipped"] += 1
                    return None
                size = 8
            else:
                size = (data[1] + 2) * 4 if transport == 51 else (data[1] + 1) * 8
            if len(data) < size:
                counts["incomplete_ipv6_extension_headers"] += 1
                return None
            data, transport = data[size:], next_header
    else:
        counts["non_ip_packets"] += 1
        return None
    if transport != 17:
        counts["non_udp_packets"] += 1
        if transport == 6 and len(data) >= 4 and 53 in struct.unpack_from("!HH", data):
            counts["dns_tcp_packets_skipped"] += 1
        return None
    if len(data) < 8:
        counts["incomplete_udp_headers"] += 1
        return None
    source_port, destination_port, length, _ = struct.unpack_from("!HHHH", data)
    if length < 8:
        counts["invalid_udp_lengths"] += 1
        return None
    if 53 not in (source_port, destination_port):
        counts["non_port53_udp_packets"] += 1
        return None
    counts["dns_udp_packets"] += 1
    counts["dns_udp_payload_truncated_packets"] += int(len(data) < length)
    return source, source_port, destination, destination_port, data[8:length]


def source_group(path):
    parts = path.parts
    if "raw" in parts:
        position = parts.index("raw") + 1
        if position < len(parts) - 1:
            return parts[position]
    return path.parent.name


def extract_capture(path, timeout_seconds):
    counts = Counter()
    records, pending, excluded_query_samples = [], {}, []
    metadata = {"capture": path.name, "capture_path": str(path.resolve()),
                "capture_group": source_group(path), "file_size_bytes": path.stat().st_size}
    with path.open("rb") as stream:
        metadata["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    previous_timestamp = None
    first_timestamp = last_timestamp = None
    next_cleanup = 0
    timeout_ns = int(timeout_seconds * 1_000_000_000)
    for index, timestamp, frame, truncated in read_pcap(path, metadata):
        counts["total_packets"] += 1
        counts["capture_truncated_packets"] += int(truncated)
        if previous_timestamp is not None and timestamp < previous_timestamp:
            counts["packet_timestamp_regressions"] += 1
        previous_timestamp = timestamp
        first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
        last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
        if timestamp >= next_cleanup:
            for key in list(pending):
                for question in list(pending[key]):
                    rows = pending[key][question]
                    while rows and timestamp - rows[0]["_timestamp_ns"] > timeout_ns:
                        rows.popleft()
                    if not rows:
                        del pending[key][question]
                if not pending[key]:
                    del pending[key]
            next_cleanup = timestamp + 5_000_000_000
        packet = udp_dns(frame, counts)
        if packet is None:
            continue
        source, sport, destination, dport, payload = packet
        try:
            buffer = DNSBuffer(payload)
            header = DNSHeader.parse(buffer)
        except (DNSError, BufferError):
            counts["incomplete_or_invalid_dns_headers"] += 1
            continue
        if header.opcode != 0:
            counts["nonstandard_dns_opcodes_skipped"] += 1
            continue
        direction = "response" if header.qr else "query"
        counts[f"dns_{direction}_packets"] += 1
        if header.q != 1:
            counts[f"dns_{direction}_question_count_not_one"] += 1
            if not header.qr:
                continue
        question = None
        if header.q == 1:
            try:
                parsed = DNSQuestion.parse(buffer)
                question = (str(parsed.qname).lower().rstrip("."), parsed.qtype, parsed.qclass)
            except (DNSError, BufferError, UnicodeError):
                counts[f"incomplete_or_invalid_dns_{direction}_questions"] += 1
                counts[f"dns_{direction}_question_failures_in_truncated_packets"] += int(truncated)
                if not header.qr and len(excluded_query_samples) < 5:
                    excluded_query_samples.append({
                        "packet_index": index, "timestamp_utc": utc(timestamp),
                        "captured_dns_payload_bytes": len(payload), "capture_truncated": truncated,
                    })
        if header.qr:
            key = (destination, dport, source, sport, header.id)
            candidates = {q: [row for row in rows if 0 <= timestamp - row["_timestamp_ns"] <= timeout_ns]
                          for q, rows in pending.get(key, {}).items()}
            candidates = {q: rows for q, rows in candidates.items() if rows}
            method = "question_verified"
            if question is not None:
                matches = candidates.get(question, [])
                row = matches[0] if matches else None
            elif sum(len(rows) for rows in candidates.values()) == 1 and header.q in (0, 1):
                question, matches = next(iter(candidates.items()))
                row = matches[0]
                method = "header_only_unique"
            else:
                row = None
            if row is None:
                counts["responses_without_matching_query"] += 1
                continue
            pending[key][question].remove(row)
            if not pending[key][question]:
                del pending[key][question]
            if not pending[key]:
                del pending[key]
            row.update(response_code=RCODE[header.rcode], response_code_numeric=header.rcode,
                       response_timestamp_utc=utc(timestamp),
                       response_latency_s=(timestamp - row["_timestamp_ns"]) / 1_000_000_000,
                       match_status=method, response_question_verified=method == "question_verified",
                       response_timing_ambiguous=row.get("_response_timing_ambiguous", False),
                       response_capture_truncated=truncated)
            counts[f"matched_responses_{method}"] += 1
            counts["matched_responses_with_ambiguous_query_timing"] += int(row["response_timing_ambiguous"])
            counts["dns_truncated_flag_responses"] += int(header.tc)
            continue
        if question is None:
            continue
        qname, qtype, qclass = question
        parts = EXTRACT(qname)
        label = qname.split(".")[0]
        key = (source, sport, destination, dport, header.id)
        previous = [row for row in pending.get(key, {}).get(question, [])
                    if 0 <= timestamp - row["_timestamp_ns"] <= timeout_ns]
        repeated = bool(previous)
        if repeated:
            for outstanding in previous:
                outstanding["_response_timing_ambiguous"] = True
            counts["repeated_outstanding_query_packets"] += 1
        row = {field: "" for field in FIELDS}
        row.update(capture=path.name, capture_path=str(path.resolve()), capture_group=source_group(path),
                   packet_index=index, timestamp_utc=utc(timestamp),
                   timestamp_epoch_s=f"{timestamp // 1_000_000_000}.{timestamp % 1_000_000_000:09d}",
                   client_ip=source, client_port=sport, server_ip=destination, server_port=dport,
                   qname=qname, qtype=QTYPE[qtype], qtype_numeric=qtype, qclass=qclass,
                   registered_domain=f"{parts.domain}.{parts.suffix}" if parts.domain and parts.suffix else "",
                   qname_length=len(qname), leftmost_label_length=len(label),
                   leftmost_label_entropy=entropy(label),
                   subdomain_label_count=len(parts.subdomain.split(".")) if parts.subdomain else 0,
                   match_status="unmatched", is_repeated_outstanding_query=repeated,
                   query_capture_truncated=truncated, _timestamp_ns=timestamp,
                   _response_timing_ambiguous=repeated)
        records.append(row)
        pending.setdefault(key, {}).setdefault(question, deque()).append(row)
    records.sort(key=lambda row: (row["_timestamp_ns"], row["packet_index"]))
    last_client_query = {}
    for row in records:
        previous = last_client_query.get(row["client_ip"])
        if previous is not None:
            row["time_since_prev_query_s"] = (row["_timestamp_ns"] - previous) / 1_000_000_000
        last_client_query[row["client_ip"]] = row["_timestamp_ns"]
    matched = sum(row["response_code"] != "" for row in records)
    metadata.update(
        capture_start_utc=utc(first_timestamp) if first_timestamp is not None else None,
        capture_end_utc=utc(last_timestamp) if last_timestamp is not None else None,
        observation_start_utc=records[0]["timestamp_utc"] if records else None,
        observation_end_utc=records[-1]["timestamp_utc"] if records else None,
        counts=dict(sorted(counts.items())), extracted_observations=len(records),
        matched_observations=matched, unmatched_observations=len(records) - matched,
        response_match_rate=matched / len(records) if records else None,
        query_question_extraction_rate=len(records) / counts["dns_query_packets"] if counts["dns_query_packets"] else None,
        match_status_counts=dict(Counter(row["match_status"] for row in records)),
        qtype_counts=dict(Counter(row["qtype"] for row in records)),
        response_code_counts=dict(Counter(row["response_code"] or "UNKNOWN" for row in records)),
        clients=sorted({row["client_ip"] for row in records}),
        excluded_query_samples=excluded_query_samples,
    )
    return records, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", nargs="+", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path,
                        default=Path(__file__).resolve().parent / "data/cic_bell_exf_2021/processed")
    parser.add_argument("--response-timeout-s", type=float, default=30)
    args = parser.parse_args()
    if not 0 < args.response_timeout_s < float("inf"):
        parser.error("--response-timeout-s must be finite and positive")
    paths = [path.resolve() for path in args.input]
    if len(set(paths)) != len(paths):
        parser.error("duplicate input captures are not allowed")
    for path in paths:
        if not path.is_file():
            parser.error(f"input not found: {path}")
    all_records, captures = [], []
    try:
        for path in paths:
            print(f"Processing {path.name} ...", flush=True)
            records, audit = extract_capture(path, args.response_timeout_s)
            all_records.extend(records)
            captures.append(audit)
            print(f"  {len(records):,} observations; {audit['matched_observations']:,} responses matched", flush=True)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"Extraction failed; outputs not replaced: {error}\n")
    all_records.sort(key=lambda row: (row["capture_path"], row["_timestamp_ns"], row["packet_index"]))
    warnings = []
    for capture in captures:
        counts = capture["counts"]
        for key, description in (
            ("capture_truncated_packets", "packets were cut short by capture snapshot length"),
            ("incomplete_or_invalid_dns_query_questions", "DNS queries could not provide a complete question"),
            ("matched_responses_header_only_unique", "responses matched by tuple/ID without question verification"),
            ("dns_tcp_packets_skipped", "DNS-over-TCP packets were excluded"),
            ("fragmented_ip_packets_skipped", "fragmented IP packets were excluded"),
            ("packet_timestamp_regressions", "packet timestamps moved backwards in capture order"),
            ("matched_responses_with_ambiguous_query_timing", "response matches have ambiguous timing because identical queries were outstanding"),
        ):
            if counts.get(key):
                warnings.append(f"{capture['capture']}: {counts[key]:,} {description}.")
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capture_group_is_verified_training_label": False,
        "response_timeout_seconds": args.response_timeout_s,
        "row_order": "capture_path, query timestamp, packet index (never mix captures into one sequence)",
        "time_since_prev_query_scope": "same capture and client IP, chronological extracted queries; first value blank",
        "matching": "UDP client/server IPs and ports + DNS ID + complete question when available; otherwise exactly one outstanding query; repeated identical questions match FIFO and flag ambiguous timing",
        "response_code_scope": "DNS header RCODE only; unknown/unmatched is blank, never assumed NOERROR or NXDOMAIN",
        "limitations": ["Classic Ethernet PCAP only; UDP port 53 only; no TCP or fragmented-IP reassembly.",
                        "Question/header extraction does not require complete answer sections; capture truncation remains flagged.",
                        "EDNS extended RCODE is not decoded; response code uses the four-bit DNS header field.",
                        "Header-only matching is weaker evidence; filter response_question_verified for strict matching.",
                        "Repeated outstanding questions may be retransmissions or duplicate capture packets; their FIFO response latency is ambiguous and explicitly flagged.",
                        "Feature values and query gaps describe extracted queries; missing queries can bias training.",
                        "Attack timestamps, per-packet labels, features, sequence length and train/test splits remain unverified."],
        "total_captures": len(captures), "total_observations": len(all_records),
        "total_matched_observations": sum(capture["matched_observations"] for capture in captures),
        "total_unmatched_observations": sum(capture["unmatched_observations"] for capture in captures),
        "warnings": warnings, "captures": captures,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_dir / "dns_observations.csv"
    audit_path = args.output_dir / "extraction_audit.json"
    csv_temp, audit_temp = csv_path.with_suffix(".csv.tmp"), audit_path.with_suffix(".json.tmp")
    with csv_temp.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_records)
    audit_temp.write_text(json.dumps(report, indent=2), encoding="utf-8")
    csv_temp.replace(csv_path)
    audit_temp.replace(audit_path)
    print(f"Wrote {csv_path}\nWrote {audit_path}", flush=True)


if __name__ == "__main__":
    main()
