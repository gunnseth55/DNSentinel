"""Streaming TShark DNS extraction with disk-backed, ambiguity-aware association.

Original captures, extraction v1, detectors, model and training code are never
rewritten. Ordinary DNS and mDNS are separate scopes; LLMNR/NBNS are audited,
not relabelled as ordinary DNS. No training labels are generated.
"""
import argparse
import csv
import hashlib
import ipaddress
import json
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from dnslib import DNSRecord, QTYPE, RCODE
from p1_detector import EXTRACT, entropy
from prepare_gru_dataset import FIELDS as LEGACY_FIELDS, source_group


PREFERENCES = {
    "tcp.desegment_tcp_streams": "TRUE", "tcp.reassemble_out_of_order": "TRUE",
    "dns.desegment_dns_messages": "TRUE", "ip.defragment": "TRUE", "ipv6.defragment": "TRUE",
}
FRAME_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.cap_len", "frame.len", "frame.protocols",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "udp.srcport", "udp.dstport",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "udp.stream", "tcp.segment",
    "tcp.reassembled.length", "ip.frag_offset", "ipv6.fraghdr.offset", "udp.payload",
    "_ws.short", "_ws.malformed", "tcp.analysis.retransmission",
]
EXTRA_FIELDS = [
    "observation_id", "capture_sha256", "capture_query_order", "dns_protocol", "dns_scope",
    "transport", "dns_transaction_id", "dns_id_hex", "dns_message_index", "question_index",
    "question_count", "decoded_question_count", "qname_original", "qname_encoding",
    "tcp_stream", "udp_stream", "query_timestamp_basis", "tcp_reassembly_frames_json",
    "tshark_response_in_frames_json", "tshark_retransmission", "retransmission_of_packet_index",
    "retransmission_basis", "response_matched", "response_match_method", "response_packet_index",
    "response_message_index", "response_message_count", "response_packet_indices_json",
    "response_header_rcode_numeric", "response_code_scope", "observed_response_codes_json",
    "response_code_conflict", "query_dns_tc_flag", "response_dns_tc_flag",
    "query_message_incomplete", "response_message_incomplete",
]
FIELDS = LEGACY_FIELDS + EXTRA_FIELDS


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")


def integer(value):
    text = str(value)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def timestamp_ns(text):
    value = Decimal(text) * 1_000_000_000
    if not value.is_finite() or value != value.to_integral_value():
        raise ValueError("Nonfinite timestamp or precision finer than nanoseconds")
    return int(value)


def epoch(ns):
    return f"{ns // 1_000_000_000}.{ns % 1_000_000_000:09d}"


def utc(ns):
    seconds, nanos = divmod(ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{nanos:09d}+00:00"


def find_values(tree, name):
    values = []
    if isinstance(tree, dict):
        for key, value in tree.items():
            if key == name:
                values.extend(value if isinstance(value, list) else [value])
            elif isinstance(value, (dict, list)):
                values.extend(find_values(value, name))
    elif isinstance(tree, list):
        for item in tree:
            values.extend(find_values(item, name))
    return values


def first(tree, name, default=None):
    values = find_values(tree, name)
    return values[0] if values else default


def is_true(value):
    return str(value).lower() in ("true", "1")


def question_nodes(tree):
    if isinstance(tree, dict):
        if any(key in tree for key in ("dns.qry.name", "dns.qry.type", "dns.qry.class")):
            yield tree
        else:
            for value in tree.values():
                yield from question_nodes(value)
    elif isinstance(tree, list):
        for value in tree:
            yield from question_nodes(value)


def parse_questions(message):
    result, failures = [], Counter()
    nodes = list(question_nodes(message.get("Queries", {})))
    for index, node in enumerate(nodes, 1):
        names, types, classes = (find_values(node, key) for key in
                                 ("dns.qry.name", "dns.qry.type", "dns.qry.class"))
        if len(names) != 1 or len(types) != 1 or len(classes) != 1:
            failures["incomplete_or_unaligned_question_fields"] += 1
            continue
        name = str(names[0])
        # Wireshark represents the root as <Root>; it is a real question.
        normalized = "." if name in ("", ".", "<Root>") else name.removesuffix(".").lower()
        try:
            qtype, qclass = integer(types[0]), integer(classes[0])
        except (TypeError, ValueError):
            failures["invalid_numeric_question_fields"] += 1
            continue
        if not (0 <= qtype <= 65535 and 0 <= qclass <= 65535):
            failures["invalid_numeric_question_fields"] += 1
            continue
        if "\\" not in normalized and normalized != ".":
            labels = normalized.split(".")
            if any(not label or len(label.encode("utf-8")) > 63 for label in labels) or len(normalized.encode("utf-8")) > 253:
                failures["invalid_qname_length_or_empty_label"] += 1
                continue
        result.append({"index": index, "name": normalized, "original": name,
                       "type": qtype, "class": qclass,
                       "encoding": "tshark_escaped" if "\\" in normalized else "text"})
    return result, failures, len(nodes)


def json_packets(stream):
    """Incrementally decode TShark's JSON array; never load a capture's JSON."""
    decoder = json.JSONDecoder()
    buffer, started, finished, eof = "", False, False, False
    while not finished:
        buffer = buffer.lstrip()
        if not started and buffer:
            if not buffer.startswith("["):
                raise ValueError("TShark output is not a JSON array")
            buffer, started = buffer[1:], True
            continue
        if started and buffer.startswith(","):
            buffer = buffer[1:]
            continue
        if started and buffer.startswith("]"):
            finished = True
            break
        if started and buffer:
            try:
                packet, position = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    raise ValueError("Incomplete TShark JSON output") from None
            else:
                yield packet
                buffer = buffer[position:]
                continue
        if eof:
            raise ValueError("Missing end of TShark JSON output")
        chunk = stream.read(65536)
        eof = not chunk
        buffer += chunk
    if buffer[1:].strip() or stream.read().strip():
        raise ValueError("Unexpected data after TShark JSON array")


def tshark_base(args, path):
    command = [str(args.tshark), "-n", "-2", "-r", str(path)]
    for key, value in PREFERENCES.items():
        command += ["-o", f"{key}:{value}"]
    for transport in ("udp", "tcp"):
        for port in getattr(args, f"decode_as_{transport}"):
            if not 1 <= port <= 65535:
                raise ValueError("Decode-as ports must be in 1-65535")
            command += ["-d", f"{transport}.port=={port},dns"]
    return command


@contextmanager
def tshark_stream(command, error_path):
    # stderr goes to a separate file, avoiding a blocked pipe during streaming.
    with Path(error_path).open("wb") as error_file:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error_file,
                                   text=True, encoding="utf-8", errors="strict")
        try:
            yield process.stdout
            if process.wait() != 0:
                raise RuntimeError(f"TShark failed; inspect {error_path}")
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                process.wait()


def create_stage(connection):
    connection.executescript("""
        PRAGMA journal_mode=DELETE;
        PRAGMA temp_store=FILE;
        PRAGMA cache_size=-16384;
        CREATE TABLE frames (
            frame INTEGER PRIMARY KEY, ns INTEGER, captured INTEGER, original INTEGER,
            family TEXT, transport TEXT, src TEXT, sport INTEGER, dst TEXT, dport INTEGER,
            stream TEXT, segments TEXT, protocols TEXT
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY, frame INTEGER, pdu INTEGER, ns INTEGER, family TEXT,
            transport TEXT, src TEXT, sport INTEGER, dst TEXT, dport INTEGER, stream TEXT,
            response INTEGER, txid INTEGER, opcode INTEGER, expected INTEGER, questions TEXT,
            signature TEXT, response_to TEXT, response_in TEXT, retransmission INTEGER,
            retransmit_in TEXT, truncated INTEGER, incomplete INTEGER, tc INTEGER,
            rcode INTEGER, header_rcode INTEGER, rcode_scope TEXT, repeat_query INTEGER DEFAULT 0,
            timing_ambiguous INTEGER DEFAULT 0, repeat_of INTEGER,
            UNIQUE(frame,pdu)
        );
        CREATE INDEX message_transaction ON messages
            (response,family,transport,stream,txid,src,sport,dst,dport,ns);
        CREATE INDEX message_frame ON messages(frame);
        CREATE TABLE links(query_id INTEGER, response_id INTEGER UNIQUE, method TEXT, verified INTEGER);
        CREATE INDEX query_links ON links(query_id);
    """)


def suspicious_nonstandard_payload(payload):
    """Only nominate a complete parse for manual decode-as review, not a row."""
    try:
        data = bytes.fromhex(payload.replace(":", ""))
        if not 12 <= len(data) <= 65535:
            return False
        record = DNSRecord.parse(data)
        if record.header.opcode != 0 or not 1 <= len(record.questions) <= 16:
            return False
        return all(question.qclass in (1, 3, 4, 254, 255) for question in record.questions)
    except Exception:
        return False


def audit_frames(args, path, connection, report):
    command = tshark_base(args, path) + ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a"]
    for field in FRAME_FIELDS:
        command += ["-e", field]
    report["commands"]["all_packet_audit"] = command
    counts, stacks, port_pairs, service_ports, excluded = (Counter() for _ in range(5))
    samples, previous, batch = [], None, []
    with tshark_stream(command, args.output_dir / (path.stem + ".audit.stderr.log")) as stream:
        for line in stream:
            values = line.rstrip("\r\n").split("\t")
            if len(values) != len(FRAME_FIELDS):
                raise ValueError("Unexpected TShark frame field count")
            row = {name: value if name == "tcp.segment" else value.rsplit(",", 1)[-1]
                   for name, value in zip(FRAME_FIELDS, values)}
            index, ns = integer(row["frame.number"]), timestamp_ns(row["frame.time_epoch"])
            captured, original = integer(row["frame.cap_len"]), integer(row["frame.len"])
            protocols = row["frame.protocols"].split(":")
            counts["total_packets"] += 1
            counts["capture_truncated_packets"] += int(captured < original)
            counts["packet_timestamp_regressions"] += int(previous is not None and ns < previous)
            previous = ns
            stacks[row["frame.protocols"]] += 1
            counts["malformed_frames"] += int(bool(row["_ws.malformed"]))
            counts["short_capture_frames"] += int(bool(row["_ws.short"]))
            counts["tcp_retransmitted_segment_frames"] += int(bool(row["tcp.analysis.retransmission"]))
            for tag in ("llmnr", "nbns", "nbdgm", "mdns", "dns", "tcp", "udp"):
                counts[tag + "_frames"] += int(tag in protocols)
            transport = next((tag for tag in reversed(protocols) if tag in ("udp", "tcp")), "")
            if transport:
                sport = row[transport + ".srcport"]
                dport = row[transport + ".dstport"]
                if sport and dport:
                    port_pairs[f"{transport}:{sport}->{dport}"] += 1
                    for port in set((sport, dport)):
                        if int(port) < 1024 or port in ("5353", "5355", "1900", "3702", "853", "5300"):
                            service_ports[f"{transport}:{port}"] += 1
                    if "53" in (sport, dport) and "dns" not in protocols:
                        counts[transport + "_port53_frames_not_dissected_as_dns"] += 1
                else:
                    counts["transport_headers_incomplete"] += 1
            family = "dns" if "dns" in protocols else "mdns" if "mdns" in protocols else ""
            if family:
                src = row["ip.src"] or row["ipv6.src"]
                dst = row["ip.dst"] or row["ipv6.dst"]
                sport, dport = row.get(transport + ".srcport", ""), row.get(transport + ".dstport", "")
                if not (src and dst and sport and dport and transport):
                    counts["dns_family_missing_transport_or_endpoints"] += 1
                    # Keep a placeholder: DNS dissection will explicitly exclude it.
                if family == "dns" and sport and dport and "53" not in (sport, dport):
                    counts["ordinary_dns_nonstandard_port_frames"] += 1
                batch.append((index, ns, captured, original, family, transport, src,
                              int(sport) if sport else None, dst, int(dport) if dport else None,
                              row.get(transport + ".stream", ""), row["tcp.segment"], row["frame.protocols"]))
                if len(batch) >= 1000:
                    connection.executemany("INSERT INTO frames VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                    connection.commit()
                    batch.clear()
            elif "llmnr" in protocols:
                excluded["llmnr_separate_name_resolution_protocol"] += 1
            elif "nbns" in protocols or "nbdgm" in protocols:
                excluded["netbios_separate_protocol"] += 1
            elif transport == "udp" and "data" in protocols and row["udp.payload"]:
                if suspicious_nonstandard_payload(row["udp.payload"]):
                    counts["possible_dns_on_undissected_udp"] += 1
                    if len(samples) < 20:
                        samples.append({"frame": index, "source_port": row["udp.srcport"],
                                        "destination_port": row["udp.dstport"],
                                        "capture_truncated": captured < original})
    if batch:
        connection.executemany("INSERT INTO frames VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
        connection.commit()
    report.update(frame_counts=dict(counts), protocol_distribution=dict(stacks),
                  relevant_service_ports=dict(sorted(service_ports.items())),
                  top_transport_port_pairs=dict(port_pairs.most_common(25)),
                  distinct_transport_port_pairs=len(port_pairs),
                  separately_audited_non_dns_protocol_frames=dict(excluded),
                  possible_nonstandard_dns_candidates=samples)


def ingest_dns(args, path, connection, report):
    command = tshark_base(args, path) + ["-Y", "dns || mdns", "-T", "json",
                                       "--no-duplicate-keys", "-J", "frame dns mdns"]
    report["commands"]["dns_message_extraction"] = command
    counts, excluded, examples, batch = Counter(), Counter(), [], []
    with tshark_stream(command, args.output_dir / (path.stem + ".dns.stderr.log")) as stream:
        for packet in json_packets(stream):
            layers = packet["_source"]["layers"]
            index = integer(first(layers["frame"], "frame.number"))
            frame = connection.execute("SELECT * FROM frames WHERE frame=?", (index,)).fetchone()
            if frame is None:
                raise ValueError("JSON DNS frame missing from independent all-frame audit")
            pdu = 0
            for family in ("dns", "mdns"):
                messages = layers.get(family, [])
                messages = messages if isinstance(messages, list) else [messages]
                for message in messages:
                    pdu += 1
                    if not isinstance(message, dict) or "filtered" in message:
                        continue
                    flag = first(message, "dns.flags.response")
                    txid, opcode, expected = (first(message, field) for field in
                                              ("dns.id", "dns.flags.opcode", "dns.count.queries"))
                    if flag is None or txid is None or opcode is None or expected is None:
                        excluded[family + "_message_incomplete_header"] += 1
                        continue
                    response = int(is_true(flag))
                    counts[family + ("_responses" if response else "_queries")] += 1
                    counts[family + "_" + (frame["transport"] or "unsupported") + "_messages"] += 1
                    questions, failures, node_count = parse_questions(message)
                    expected = integer(expected)
                    parsed = len(questions)
                    if not response:
                        counts[family + "_declared_query_questions"] += expected
                        counts[family + "_decoded_query_questions"] += parsed
                        missing = max(0, expected - parsed)
                        if missing:
                            reason = "capture_truncated_question" if frame["captured"] < frame["original"] else "malformed_or_unsupported_question"
                            excluded[family + "_" + reason] += missing
                            if len(examples) < 10:
                                examples.append({"frame": index, "protocol": family, "expected_questions": expected,
                                                 "decoded_questions": parsed, "reason": reason})
                        counts[family + "_query_messages_with_complete_questions"] += int(parsed > 0)
                        counts[family + "_multi_question_queries"] += int(expected > 1)
                        for reason, number in failures.items():
                            counts[family + "_" + reason] += number
                    if expected > 65535 or parsed > expected:
                        raise ValueError("TShark question count/alignment inconsistency")
                    if integer(opcode) != 0:
                        excluded[family + "_unsupported_opcode_query_questions"] += parsed if not response else 0
                        continue
                    if not response and expected == 0:
                        excluded[family + "_query_without_questions"] += 1
                        continue
                    if not (frame["transport"] in ("udp", "tcp") and frame["src"] and frame["dst"] and
                            frame["sport"] is not None and frame["dport"] is not None):
                        excluded[family + "_unsupported_transport_query_questions"] += parsed if not response else 0
                        continue
                    if family == "mdns" and args.exclude_mdns:
                        excluded["mdns_explicitly_excluded_query_questions"] += parsed if not response else 0
                        continue
                    if not response and not parsed:
                        continue
                    header_code = first(message, "dns.flags.rcode") if response else None
                    extended = first(message, "dns.resp.ext_rcode") if response else None
                    incomplete = any(key in layers for key in ("_ws.short", "_ws.malformed"))
                    incomplete = incomplete or bool(find_values(message, "_ws.malformed"))
                    code = integer(header_code) if header_code is not None else None
                    scope = "header_only_extended_unknown" if incomplete else "header_complete"
                    if code is not None and extended is not None:
                        code |= integer(extended) << 4
                        scope = "header_plus_opt_extended"
                    signature = json.dumps([[q["name"], q["type"], q["class"]] for q in questions], separators=(",", ":")) if parsed == expected else ""
                    response_to = find_values(message, "dns.response_to")
                    response_in = find_values(message, "dns.response_in")
                    retransmit_in = find_values(message, "dns.retransmit_request_in")
                    retransmission = is_true(first(message, "dns.retransmission", "False")) or bool(retransmit_in)
                    batch.append((index, pdu, frame["ns"], family, frame["transport"], frame["src"], frame["sport"],
                                  frame["dst"], frame["dport"], frame["stream"], response, integer(txid), integer(opcode),
                                  expected, json.dumps(questions), signature, json.dumps(response_to), json.dumps(response_in),
                                  int(retransmission), json.dumps(retransmit_in), int(frame["captured"] < frame["original"]),
                                  int(incomplete), int(is_true(first(message, "dns.flags.truncated", "False"))), code,
                                  integer(header_code) if header_code is not None else None, scope))
                    if len(batch) >= 1000:
                        insert_messages(connection, batch)
                        batch.clear()
    if batch:
        insert_messages(connection, batch)
    connection.commit()
    report.update(dns_counts=dict(counts), exclusion_reasons=dict(excluded), excluded_question_samples=examples)
    # Both passes use identical dissection preferences and identify frames by ID.
    detected = report["frame_counts"].get("dns_frames", 0) + report["frame_counts"].get("mdns_frames", 0)
    report["validation"] = {"dns_family_frame_ids_accounted_for": detected == connection.execute("SELECT COUNT(*) FROM frames").fetchone()[0]}


def insert_messages(connection, batch):
    connection.executemany("""INSERT INTO messages
        (frame,pdu,ns,family,transport,src,sport,dst,dport,stream,response,txid,opcode,expected,
         questions,signature,response_to,response_in,retransmission,retransmit_in,truncated,incomplete,
         tc,rcode,header_rcode,rcode_scope) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", batch)


def association_candidates(connection, response, timeout_ns):
    return connection.execute("""SELECT q.* FROM messages q
        WHERE q.response=0 AND q.family=? AND q.transport=? AND q.stream=? AND q.txid=?
          AND q.src=? AND q.sport=? AND q.dst=? AND q.dport=?
          AND q.ns BETWEEN ? AND ? ORDER BY q.ns,q.frame,q.pdu""", (
        response["family"], response["transport"], response["stream"], response["txid"],
        response["dst"], response["dport"], response["src"], response["sport"],
        response["ns"] - timeout_ns, response["ns"],
    )).fetchall()


def questions_agree(query, response, allow_missing=False):
    if query["signature"] and response["signature"]:
        return query["signature"] == response["signature"]
    rq = {q["index"]: (q["name"], q["type"], q["class"]) for q in json.loads(response["questions"])}
    qq = {q["index"]: (q["name"], q["type"], q["class"]) for q in json.loads(query["questions"])}
    common = set(qq) & set(rq)
    return all(qq[i] == rq[i] for i in common) and (bool(common) or allow_missing)


def associate(connection, args, report):
    counts = Counter()
    timeout_ns = int(Decimal(str(args.response_timeout_s)) * 1_000_000_000)
    for response in connection.execute("SELECT * FROM messages WHERE response=1 ORDER BY ns,frame,pdu"):
        if response["family"] == "mdns":
            counts["mdns_responses_not_forced_into_unicast_pairing"] += 1
            continue
        candidates = association_candidates(connection, response, timeout_ns)
        refs = {integer(value) for value in json.loads(response["response_to"])}
        linked = [q for q in candidates if q["frame"] in refs]
        method = "tshark_response_to"
        if not refs:
            linked = [q for q in candidates if response["frame"] in
                      {integer(value) for value in json.loads(q["response_in"])}]
            method = "tshark_response_in"
        if refs or linked:
            selected = [q for q in linked if questions_agree(q, response, allow_missing=True)]
            if len(selected) != 1:
                counts["tshark_association_ambiguous_or_failed_validation"] += 1
                for query in selected:
                    connection.execute("UPDATE messages SET timing_ambiguous=1 WHERE id=?", (query["id"],))
                continue
            query = selected[0]
            verified = int(bool(query["signature"]) and query["signature"] == response["signature"])
        else:
            # No FIFO guess when several queries share a transaction/question.
            selected = [q for q in candidates if q["signature"] and q["signature"] == response["signature"]
                        and not connection.execute("SELECT 1 FROM links WHERE query_id=?", (q["id"],)).fetchone()]
            if len(selected) != 1:
                counts["responses_without_unique_validated_query"] += 1
                if len(selected) > 1:
                    counts["ambiguous_transaction_responses"] += 1
                    for query in selected:
                        connection.execute("UPDATE messages SET timing_ambiguous=1 WHERE id=?", (query["id"],))
                continue
            query, method, verified = selected[0], "unique_transaction_question", 1
        connection.execute("INSERT INTO links VALUES (?,?,?,?)", (query["id"], response["id"], method, verified))
        counts[method] += 1
        counts["links_with_question_verification"] += verified
    # Identify repeats in chronological order, independently of file order.
    pending = {}
    for query in connection.execute("SELECT * FROM messages WHERE response=0 ORDER BY ns,frame,pdu"):
        key = tuple(query[name] for name in ("family", "transport", "stream", "txid", "src", "sport", "dst", "dport", "signature"))
        if not query["signature"] or query["family"] == "mdns":
            continue
        old = pending.get(key, [])
        old = [(identity, ns, frame, replied) for identity, ns, frame, replied in old
               if query["ns"] - ns <= timeout_ns and (replied is None or replied >= query["ns"])]
        if old:
            counts["repeated_outstanding_query_messages"] += 1
            connection.execute("UPDATE messages SET repeat_query=1,timing_ambiguous=1,repeat_of=? WHERE id=?",
                               (old[0][2], query["id"]))
            for identity, _, _, _ in old:
                connection.execute("UPDATE messages SET timing_ambiguous=1 WHERE id=?", (identity,))
        replied = connection.execute("SELECT MIN(r.ns) FROM links l JOIN messages r ON r.id=l.response_id WHERE l.query_id=?",
                                     (query["id"],)).fetchone()[0]
        old.append((query["id"], query["ns"], query["frame"], replied))
        pending[key] = old
        if len(pending) > 5000:
            pending = {key: values for key, values in pending.items()
                       if any(query["ns"] - item[1] <= timeout_ns for item in values)}
    connection.commit()
    report["association_counts"] = dict(counts)


def export_capture(connection, writer, report):
    counts, matches, scope_counts, type_counts = Counter(), Counter(), Counter(), Counter()
    previous, previous_order = {}, None
    query_order = {row["id"]: index for index, row in enumerate(
        connection.execute("SELECT id FROM messages WHERE response=0 ORDER BY frame,pdu"), 1)}
    # This small map indexes only decoded query messages, not whole packet data.
    row_identity = set()
    for query in connection.execute("SELECT * FROM messages WHERE response=0 ORDER BY ns,frame,pdu"):
        responses = connection.execute("""SELECT r.*,l.method,l.verified FROM links l
            JOIN messages r ON r.id=l.response_id WHERE l.query_id=? ORDER BY r.ns,r.frame,r.pdu""", (query["id"],)).fetchall()
        response = responses[0] if responses else None
        codes = sorted({r["rcode"] for r in responses if r["rcode"] is not None})
        conflict = len(codes) > 1
        if response:
            counts["matched_query_messages"] += 1
        counts["decoded_query_messages"] += 1
        frame = connection.execute("SELECT * FROM frames WHERE frame=?", (query["frame"],)).fetchone()
        response_questions = ({q["index"]: q for q in json.loads(response["questions"])} if response else {})
        questions = json.loads(query["questions"])
        for question in questions:
            identity = (query["frame"], query["pdu"], question["index"])
            if identity in row_identity:
                raise ValueError("Duplicate DNS message/question identity")
            row_identity.add(identity)
            ordering = (query["ns"], *identity)
            if previous_order is not None and ordering < previous_order:
                raise ValueError("Nonchronological observation export")
            previous_order = ordering
            name, qtype = question["name"], question["type"]
            parts = EXTRACT(name) if name != "." else None
            label = name.split(".")[0] if name != "." else ""
            same_question = response_questions.get(question["index"])
            verified = bool(response and same_question and all(same_question[k] == question[k] for k in ("name", "type", "class")))
            verified = verified and not conflict
            if conflict:
                status = "response_code_conflict"
            elif response:
                status = "question_verified" if verified else "associated_question_unverified"
            elif query["family"] == "mdns":
                status = "unmatched_multicast"
            elif query["timing_ambiguous"]:
                status = "unmatched_ambiguous"
            else:
                status = "unmatched"
            code = codes[0] if len(codes) == 1 else None
            refs = json.loads(query["retransmit_in"])
            scope = "multicast_dns" if query["family"] == "mdns" else "unicast_dns"
            row = {field: "" for field in FIELDS}
            gap_key = (query["src"], query["family"])
            # Separate question rows in one DNS message share one arrival time.
            gap = (query["ns"] - previous[gap_key]) / 1_000_000_000 if gap_key in previous else ""
            previous[gap_key] = query["ns"]
            row.update(capture=report["capture"], capture_path=report["capture_path"], capture_group=report["capture_group"],
                       packet_index=query["frame"], timestamp_utc=utc(query["ns"]), timestamp_epoch_s=epoch(query["ns"]),
                       client_ip=query["src"], client_port=query["sport"], server_ip=query["dst"], server_port=query["dport"],
                       qname=name, qtype=QTYPE[qtype], qtype_numeric=qtype, qclass=question["class"],
                       registered_domain=f"{parts.domain}.{parts.suffix}" if parts and parts.domain and parts.suffix else "",
                       qname_length=len(name), leftmost_label_length=len(label), leftmost_label_entropy=entropy(label),
                       subdomain_label_count=len(parts.subdomain.split(".")) if parts and parts.subdomain else 0,
                       time_since_prev_query_s=gap, match_status=status, response_question_verified=verified,
                       is_repeated_outstanding_query=bool(query["repeat_query"]),
                       response_timing_ambiguous=bool(query["timing_ambiguous"]), query_capture_truncated=bool(query["truncated"]),
                       observation_id=f"{report['sha256']}:{query['frame']}:{query['pdu']}:{question['index']}",
                       capture_sha256=report["sha256"], capture_query_order=query_order[query["id"]],
                       dns_protocol=query["family"], dns_scope=scope, transport=query["transport"],
                       dns_transaction_id=query["txid"], dns_id_hex=f"0x{query['txid']:04x}",
                       dns_message_index=query["pdu"], question_index=question["index"],
                       question_count=query["expected"], decoded_question_count=len(questions),
                       qname_original=question["original"], qname_encoding=question["encoding"],
                       tcp_stream=query["stream"] if query["transport"] == "tcp" else "",
                       udp_stream=query["stream"] if query["transport"] == "udp" else "",
                       query_timestamp_basis="tshark_dns_pdu_completion_frame" if query["transport"] == "tcp" else "captured_datagram_frame",
                       tcp_reassembly_frames_json=json.dumps(frame["segments"].split(",") if frame["segments"] else []),
                       tshark_response_in_frames_json=query["response_in"], tshark_retransmission=bool(query["retransmission"]),
                       retransmission_of_packet_index=integer(refs[0]) if refs else query["repeat_of"] if query["repeat_of"] else "",
                       retransmission_basis="tshark" if query["retransmission"] else "repeated_transaction_candidate" if query["repeat_query"] else "not_flagged",
                       response_matched=bool(response), response_message_count=len(responses),
                       response_packet_indices_json=json.dumps([r["frame"] for r in responses]),
                       observed_response_codes_json=json.dumps(codes), response_code_conflict=conflict,
                       query_dns_tc_flag=bool(query["tc"]), query_message_incomplete=bool(query["incomplete"]))
            if response:
                row.update(response_code=RCODE.forward.get(code, f"RCODE{code}") if code is not None else "", response_code_numeric=code if code is not None else "",
                           response_timestamp_utc=utc(response["ns"]), response_latency_s=(response["ns"] - query["ns"]) / 1_000_000_000,
                           response_capture_truncated=bool(response["truncated"]), response_match_method=response["method"],
                           response_packet_index=response["frame"], response_message_index=response["pdu"],
                           response_header_rcode_numeric=response["header_rcode"] if response["header_rcode"] is not None else "",
                           response_code_scope=response["rcode_scope"], response_dns_tc_flag=bool(response["tc"]),
                           response_message_incomplete=bool(response["incomplete"]))
            if not response and (row["response_code"] or row["response_code_numeric"] != ""):
                raise ValueError("Fabricated response code on unmatched query")
            if row["response_latency_s"] != "" and row["response_latency_s"] < 0:
                raise ValueError("Negative matched response latency")
            ipaddress.ip_address(row["client_ip"])
            ipaddress.ip_address(row["server_ip"])
            writer.writerow(row)
            counts["observations"] += 1
            counts["matched_observations"] += int(response is not None)
            counts["unmatched_observations"] += int(response is None)
            counts["multi_question_observations"] += int(query["expected"] > 1)
            counts["response_code_conflicts"] += int(conflict)
            scope_counts[scope] += 1
            type_counts[QTYPE[qtype]] += 1
            matches[status] += 1
    report.update(output_counts=dict(counts), observation_scope_counts=dict(scope_counts),
                  qtype_counts=dict(type_counts), match_status_counts=dict(matches))
    report["validation"].update(unique_observation_ids=True, chronological_output=True,
                                valid_ip_and_numeric_question_fields=True, unmatched_responses_remain_blank=True,
                                nonnegative_response_latency=True)


def protected_paths(project, inputs, legacy_dir):
    paths = set(inputs)
    paths.add(Path(__file__).resolve())
    for name in ("dns_server.py", "dns_client.py", "security.py", "behavior.py", "b1_detector.py", "p1_detector.py",
                 "prepare_gru_dataset.py", "build_gru_sequences.py", "models/gru/m1_benign_ae/best.pt"):
        path = project / name
        if path.is_file():
            paths.add(path)
    paths.update((project / "ml").glob("*.py"))
    paths.update(path for path in (project / "configs").rglob("*") if path.is_file())
    paths.update(path for path in (project / "models/gru").rglob("*") if path.is_file())
    paths.update(path for path in legacy_dir.rglob("*") if path.is_file())
    for suffix in ("*.csv", "*.json"):
        paths.update((project / "data/cic_bell_exf_2021/processed").glob(suffix))
    return {str(path.resolve()): digest(path) for path in sorted(paths)}


def run(args):
    project = Path(__file__).resolve().parent
    args.tshark = args.tshark or shutil.which("tshark") or Path("C:/Program Files/Wireshark/tshark.exe")
    if not Path(args.tshark).is_file():
        raise ValueError("TShark not found; provide --tshark with its installed executable path")
    paths = sorted((path.resolve() for path in (args.input or args.raw_dir.rglob("*.pcap"))), key=str)
    if not paths or len(paths) != len(set(paths)) or any(not path.is_file() for path in paths):
        raise ValueError("Supply existing, distinct PCAP input files")
    if not 0 < args.response_timeout_s < float("inf"):
        raise ValueError("response-timeout-s must be positive and finite")
    args.output_dir = args.output_dir.resolve()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise ValueError("Output is not empty; choose a new output directory to preserve previous results")
    if args.legacy_dir.resolve() == args.output_dir or args.output_dir in [path.parent for path in paths]:
        raise ValueError("Output cannot replace legacy extraction or raw capture directories")
    baseline = json.loads((args.legacy_dir / "extraction_audit.json").read_text(encoding="utf-8"))
    old = {item["capture"]: item for item in baseline["captures"]}
    before = protected_paths(project, paths, args.legacy_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "preservation_manifest.json", {"status": "started", "before_sha256": before})
    version = subprocess.run([str(args.tshark), "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    reports, comparisons, capture_hashes = [], [], set()
    csv_temp = args.output_dir / "dns_observations.csv.tmp"
    with csv_temp.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        for path in paths:
            print(f"Auditing and extracting {path.name} ...", flush=True)
            source_hash = before[str(path)]
            if source_hash in capture_hashes:
                raise ValueError("Duplicate input capture content; refusing duplicate observations")
            capture_hashes.add(source_hash)
            report = {"capture": path.name, "capture_path": str(path), "capture_group": source_group(path),
                      "sha256": source_hash, "file_size_bytes": path.stat().st_size, "commands": {}}
            work = args.output_dir / ".extraction_work.sqlite3"
            with sqlite3.connect(work) as connection:
                connection.row_factory = sqlite3.Row
                create_stage(connection)
                audit_frames(args, path, connection, report)
                ingest_dns(args, path, connection, report)
                associate(connection, args, report)
                export_capture(connection, writer, report)
            # Context managers commit but do not close sqlite connections.
            connection.close()
            work.unlink()
            output.flush()
            ordinary = report["observation_scope_counts"].get("unicast_dns", 0)
            multicast = report["observation_scope_counts"].get("multicast_dns", 0)
            excluded = report["exclusion_reasons"]
            explanation = f"{excluded.get('dns_capture_truncated_question', 0)} ordinary-DNS questions incomplete in truncated captures"
            if multicast:
                explanation += f"; {multicast} separately tagged mDNS questions"
            if report["frame_counts"].get("possible_dns_on_undissected_udp"):
                explanation += "; nonstandard UDP candidates require explicit review"
            comparisons.append({"capture": path.name, "capture_group": source_group(path),
                                "old_queries": old.get(path.name, {}).get("extracted_observations", ""),
                                "new_queries": report["output_counts"].get("observations", 0),
                                "new_unicast_dns_questions": ordinary, "new_mdns_questions": multicast,
                                "dns_responses": report["dns_counts"].get("dns_responses", 0),
                                "mdns_responses": report["dns_counts"].get("mdns_responses", 0),
                                "still_excluded": sum(number for reason, number in excluded.items()
                                                      if reason.startswith("dns_") and ("question" in reason)),
                                "explanation": explanation})
            reports.append(report)
            print(f"  {ordinary:,} ordinary DNS + {multicast:,} mDNS question observations; "
                  f"{report['output_counts'].get('matched_observations',0):,} explicitly associated", flush=True)
    after = {name: digest(name) for name in before}
    if before != after:
        raise ValueError("Protected source/data/model files changed during extraction; outputs not finalized")
    csv_temp.replace(args.output_dir / "dns_observations.csv")
    with (args.output_dir / "extraction_comparison.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(comparisons[0]))
        writer.writeheader()
        writer.writerows(comparisons)
    totals, scopes = Counter(), Counter()
    for report in reports:
        totals.update(report["output_counts"])
        scopes.update(report["observation_scope_counts"])
    audit = {
        "schema_version": "dns-extraction-v2", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed", "tshark_version": version, "python_version": sys.version,
        "extractor_sha256": digest(__file__), "preferences": PREFERENCES,
        "response_timeout_seconds": args.response_timeout_s, "columns": FIELDS,
        "capture_group_is_verified_training_label": False, "total_captures": len(reports),
        "totals": dict(totals), "observation_scope_counts": dict(scopes), "captures": reports,
        "output_csv_sha256": digest(args.output_dir / "dns_observations.csv"),
        "ordering": "capture path, query timestamp, original frame, DNS PDU index, question index; capture_query_order preserves file order",
        "association": "TShark response_to/response_in validated against transaction/endpoints/stream/questions, else unique outstanding complete-question transaction; ambiguous replies remain unassigned; mDNS not forced into unicast pairing",
        "memory": "Streaming per-packet TShark JSON; per-capture SQLite disk staging for chronological association; no all-capture in-memory dataset",
        "schema_notes": ["One row per decodable question; a frame can contain several DNS PDUs/questions.",
                         "Use observation_id or (capture_path,packet_index,dns_message_index,question_index), not capture/frame alone, as the unique key.",
                         "dns_protocol/dns_scope separate ordinary DNS from mDNS. Filter explicitly before sequence construction.",
                         "TCP timestamps identify the frame where a reassembled DNS PDU completes, not an invented first-byte arrival time.",
                         "Original source identities and timestamps are metadata, never verified training labels.",
                         "response_code is blank for unmatched/conflicting results; all observed codes and association provenance are retained.",
                         "For truncated responses without a captured OPT record, header RCODE is explicitly marked header_only_extended_unknown."],
        "limitations": ["Capture-truncated names cannot be reconstructed; decoded header-only packets do not become complete query observations.",
                        "LLMNR/NetBIOS are audited separately, not relabelled as ordinary DNS. mDNS unsolicited replies lack reliable one-to-one query pairing.",
                        "Nonstandard DNS is included when TShark recognizes it or an explicit decode-as port is supplied; concealed/encrypted DNS cannot be ruled out.",
                        "Escaped QNAME measurements are textual; root names, multicast traffic and multi-question messages need explicit downstream policy.",
                        "No labels, sequence datasets, trained models, or gateway behaviour were changed."],
        "protected_inputs_verified_unchanged": True,
    }
    write_json(args.output_dir / "extraction_audit.json", audit)
    write_json(args.output_dir / "preservation_manifest.json", {"status": "verified_unchanged", "before_sha256": before, "after_sha256": after})
    print(f"Completed: {totals.get('observations',0):,} observations in {args.output_dir}", flush=True)


def main():
    project = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", nargs="+", type=Path)
    parser.add_argument("--raw-dir", type=Path, default=project / "data/cic_bell_exf_2021/raw")
    parser.add_argument("--legacy-dir", type=Path, default=project / "data/cic_bell_exf_2021/processed/all_captures")
    parser.add_argument("--output-dir", type=Path, default=project / "data/cic_bell_exf_2021/processed/extraction_v2")
    parser.add_argument("--tshark", type=Path)
    parser.add_argument("--response-timeout-s", type=float, default=30)
    parser.add_argument("--exclude-mdns", action="store_true")
    parser.add_argument("--decode-as-udp", type=int, action="append", default=[])
    parser.add_argument("--decode-as-tcp", type=int, action="append", default=[])
    args = parser.parse_args()
    try:
        run(args)
    except (ValueError, OSError, RuntimeError, sqlite3.Error, KeyError) as error:
        parser.exit(1, f"Extraction v2 failed; existing datasets remain unchanged: {error}\n")


if __name__ == "__main__":
    main()
