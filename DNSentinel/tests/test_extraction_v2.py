"""Small protocol regressions; synthetic fixtures never enter production output."""
import argparse
import csv
import io
import shutil
import socket
import sqlite3
import struct
import unittest
import uuid
from pathlib import Path

from dnslib import DNSQuestion, DNSRecord, EDNS0, RR, TXT

import prepare_gru_dataset_v2 as v2


TSHARK = shutil.which("tshark") or "C:/Program Files/Wireshark/tshark.exe"
PROJECT = Path(__file__).resolve().parents[1]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def ethernet_ip(payload, source="192.0.2.1", destination="192.0.2.53", protocol=17):
    source_bytes, destination_bytes = socket.inet_aton(source), socket.inet_aton(destination)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 123, 0, 64,
                         protocol, 0, source_bytes, destination_bytes)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("00112233445566778899aabb0800") + header + payload


def udp(message, source="192.0.2.1", destination="192.0.2.53", sport=42000, dport=53):
    data = message.pack() if isinstance(message, DNSRecord) else message
    return ethernet_ip(struct.pack("!HHHH", sport, dport, len(data) + 8, 0) + data,
                       source, destination)


def tcp(data, seq, ack, flags=0x18, response=False):
    source, destination = ("192.0.2.53", "192.0.2.1") if response else ("192.0.2.1", "192.0.2.53")
    sport, dport = (53, 43000) if response else (43000, 53)
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + struct.pack("!BBH", 0, 6, len(header) + len(data))
    header = header[:16] + struct.pack("!H", checksum(pseudo + header + data)) + header[18:]
    return ethernet_ip(header + data, source, destination, 6)


def question(name, identifier=100, qtype=1):
    result = DNSRecord(q=DNSQuestion(name, qtype))
    result.header.id = identifier
    return result


def reply(query, code=0):
    result = query.reply()
    result.questions = list(query.questions)
    result.header.rcode = code
    return result


@unittest.skipUnless(Path(TSHARK).is_file(), "TShark is required for protocol extraction checks")
class TestExtractionV2(unittest.TestCase):
    def setUp(self):
        self.work = PROJECT / "tests" / ("_extraction_v2_" + uuid.uuid4().hex)
        self.work.mkdir()

    def tearDown(self):
        target = self.work.resolve()
        if not target.is_relative_to((PROJECT / "tests").resolve()) or not target.name.startswith("_extraction_v2_"):
            raise RuntimeError("Unsafe test cleanup path")
        shutil.rmtree(target)

    def extract(self, packets, decode_udp=()):
        path = self.work / "fixture.pcap"
        with path.open("wb") as stream:
            stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ns, frame, captured in packets:
                size = len(frame) if captured is None else captured
                stream.write(struct.pack("<IIII", ns // 1_000_000_000, ns % 1_000_000_000 // 1000, size, len(frame)))
                stream.write(frame[:size])
        args = argparse.Namespace(tshark=Path(TSHARK), output_dir=self.work, decode_as_udp=list(decode_udp),
                                  decode_as_tcp=[], response_timeout_s=30, exclude_mdns=False)
        report = {"capture": path.name, "capture_path": str(path), "capture_group": "test_fixture",
                  "sha256": v2.digest(path), "commands": {}}
        connection = sqlite3.connect(self.work / "stage.sqlite3")
        connection.row_factory = sqlite3.Row
        try:
            v2.create_stage(connection)
            v2.audit_frames(args, path, connection, report)
            v2.ingest_dns(args, path, connection, report)
            v2.associate(connection, args, report)
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=v2.FIELDS)
            writer.writeheader()
            v2.export_capture(connection, writer, report)
        finally:
            connection.close()
        return list(csv.DictReader(io.StringIO(output.getvalue()))), report

    def test_response_before_query_in_file_order(self):
        q = question("Order.Example.test")
        packets = [(1_100_000_000, udp(reply(q, 2), "192.0.2.53", "192.0.2.1", 53, 42000), None),
                   (1_000_000_000, udp(q), None)]
        rows, audit = self.extract(packets)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["response_code"], "SERVFAIL")
        self.assertEqual(rows[0]["qname"], "order.example.test")
        self.assertEqual(rows[0]["packet_index"], "2")
        self.assertEqual(audit["frame_counts"]["packet_timestamp_regressions"], 1)

    def test_multiple_questions_and_root(self):
        q = question("same.test", 101)
        q.add_question(DNSQuestion("same.test", 1))
        r = reply(q, 3)
        root = question(".", 102, 2)
        rows, _ = self.extract([(1_000_000_000, udp(q), None),
                                (1_100_000_000, udp(r, "192.0.2.53", "192.0.2.1", 53, 42000), None),
                                (2_000_000_000, udp(root), None)])
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["question_index"] for row in rows[:2]], ["1", "2"])
        self.assertEqual([row["response_code"] for row in rows[:2]], ["NXDOMAIN", "NXDOMAIN"])
        self.assertEqual(rows[-1]["qname"], ".")
        self.assertEqual(rows[-1]["response_code"], "")
        self.assertEqual(len({row["observation_id"] for row in rows}), 3)

    def test_tcp_reassembly_and_multiple_pdus(self):
        q1, q2 = question("first.test", 201), question("second.test", 202, 28)
        def wire(message):
            data = message.pack()
            return struct.pack("!H", len(data)) + data
        data = wire(q1) + wire(q2)
        responses = wire(reply(q1)) + wire(reply(q2, 5))
        packets = [
            (1_000_000_000, tcp(b"", 1000, 0, 2), None),
            (1_010_000_000, tcp(b"", 2000, 1001, 0x12, True), None),
            (1_020_000_000, tcp(b"", 1001, 2001, 0x10), None),
            (1_030_000_000, tcp(data[:7], 1001, 2001), None),
            (1_040_000_000, tcp(data[7:], 1008, 2001), None),
            (1_050_000_000, tcp(responses[:5], 2001, 1001 + len(data), response=True), None),
            (1_060_000_000, tcp(responses[5:], 2006, 1001 + len(data), response=True), None),
        ]
        rows, audit = self.extract(packets)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["transport"] for row in rows}, {"tcp"})
        self.assertEqual({row["dns_message_index"] for row in rows}, {"1", "2"})
        self.assertEqual([row["response_code"] for row in rows], ["NOERROR", "REFUSED"])
        self.assertEqual({row["packet_index"] for row in rows}, {"5"})
        self.assertEqual(audit["dns_counts"]["dns_tcp_messages"], 4)

    def test_private_type_and_nonstandard_port(self):
        q = question("private.test", 301, 65280)
        rows, _ = self.extract([(1_000_000_000, udp(q, dport=5300), None),
                                (1_100_000_000, udp(reply(q), "192.0.2.53", "192.0.2.1", 5300, 42000), None)], [5300])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["qtype_numeric"], "65280")
        self.assertEqual(rows[0]["server_port"], "5300")
        self.assertEqual(rows[0]["response_code"], "NOERROR")

    def test_truncated_question_never_becomes_observation(self):
        q = question("a" * 63 + ".example.test", 401)
        rows, audit = self.extract([(1_000_000_000, udp(q), 96)])
        self.assertEqual(rows, [])
        self.assertEqual(audit["exclusion_reasons"]["dns_capture_truncated_question"], 1)

    def test_truncated_answer_does_not_invent_complete_response(self):
        q = question("answer.test", 402, 16)
        r = reply(q)
        r.add_answer(RR("answer.test", 16, rdata=TXT("x" * 200)))
        rows, audit = self.extract([(1_000_000_000, udp(q), None),
                                    (1_100_000_000, udp(r, "192.0.2.53", "192.0.2.1", 53, 42000), 96)])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["response_code"], "NOERROR")
        self.assertEqual(rows[0]["response_message_incomplete"], "True")
        self.assertEqual(rows[0]["response_code_scope"], "header_only_extended_unknown")
        self.assertEqual(audit["frame_counts"]["short_capture_frames"], 1)

    def test_multicast_scope_does_not_fabricate_response(self):
        q = question("printer.local", 0, 12)
        rows, audit = self.extract([(1_000_000_000, udp(q, destination="224.0.0.251", sport=5353, dport=5353), None),
                                    (1_100_000_000, udp(reply(q), "192.0.2.53", "224.0.0.251", 5353, 5353), None)])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dns_scope"], "multicast_dns")
        self.assertEqual(rows[0]["response_code"], "")
        self.assertEqual(audit["dns_counts"]["mdns_responses"], 1)

    def test_extended_rcode_and_repeated_queries_retained(self):
        q = question("repeat.test", 501)
        r = reply(q)
        r.add_ar(EDNS0(ext_rcode=1, udp_len=1232))
        rows, _ = self.extract([(1_000_000_000, udp(q), None),
                                (1_020_000_000, udp(q), None),
                                (1_100_000_000, udp(r, "192.0.2.53", "192.0.2.1", 53, 42000), None)])
        self.assertEqual(len(rows), 2)
        self.assertTrue(any(row["is_repeated_outstanding_query"] == "True" for row in rows))
        self.assertEqual(len({row["observation_id"] for row in rows}), 2)
        matched = [row for row in rows if row["response_matched"] == "True"]
        self.assertLessEqual(len(matched), 1)
        if matched:
            self.assertEqual(matched[0]["response_code_numeric"], "16")
            self.assertEqual(matched[0]["response_code_scope"], "header_plus_opt_extended")


if __name__ == "__main__":
    unittest.main()
