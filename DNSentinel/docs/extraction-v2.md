# CIC-Bell extraction v2

[Documentation index](README.md) · [Dataset and M1 context](dataset-and-m1.md)

## What changed

`prepare_gru_dataset_v2.py` is a separate extractor. The original
`prepare_gru_dataset.py`, original raw/processed data, working detectors,
training modules and existing checkpoint remain unchanged. Results go to
`data/cic_bell_exf_2021/processed/extraction_v2/`.

Two TShark passes serve different purposes:

1. An all-frame audit counts packets, protocols, transports, relevant ports,
   truncated/malformed capture indicators and recognized nonstandard DNS.
   Unclassified nonstandard UDP payloads are probed for complete DNS parses
   only as review candidates; a successful probe never silently creates a row.
2. Incrementally parsed structured JSON preserves individual DNS PDUs and
   question containers. TCP DNS and IP/TCP reassembly are enabled. Per-capture
   SQLite staging permits chronological matching and export without loading
   all packet JSON or all capture observations into Python memory.

TShark uses two-pass analysis, name resolution disabled, TCP stream/DNS message
desegmentation enabled, out-of-order TCP reassembly enabled, and IPv4/IPv6
defragmentation enabled. Exact executable version, preferences, commands,
source hashes and output hash are recorded in the audit.

Protocol documentation: [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
and [DNS fields](https://www.wireshark.org/docs/dfref/d/dns.html).

## Scope: ordinary DNS, mDNS, and other name services

Ordinary DNS on UDP/TCP is tagged `dns_protocol=dns`,
`dns_scope=unicast_dns`. Recognized DNS on nonstandard ports is included.
Explicit `--decode-as-udp PORT` / `--decode-as-tcp PORT` options support reviewed
nonstandard services. Arbitrary payloads on port 53 do not become observations
without complete parsed question fields.

mDNS on port 5353 is genuine DNS-format discovery traffic. Its decoded
questions are retained as `dns_protocol=mdns`, `dns_scope=multicast_dns`, not
mixed silently into ordinary DNS counts. Use `--exclude-mdns` with a new output
directory for an ordinary-DNS-only extraction. New background mDNS rows do not
represent recovered attack payloads or verified attack labels.

LLMNR and NetBIOS name/datagram services are counted separately in the audit.
They have different semantics and are not relabelled as ordinary DNS. Encrypted
or deliberately concealed traffic on arbitrary ports is outside this claim of
decodability. The audit reports any recognized nonstandard DNS and any complete
parse candidates requiring manual review.

## Observation identity and ordering

One row represents one decodable question. Distinct questions can share a
frame, and several TCP DNS PDUs can share a frame. Duplicate question names in
one message remain separate question slots; no synthetic requests are added.

Use the full `observation_id`, or this composite key:

```text
(capture_path, packet_index, dns_message_index, question_index)
```

The ID includes the capture's SHA-256. `capture_query_order` and the frame/PDU/
question ordinals preserve original file order. Output is sorted by capture,
query timestamp and those ordinals. Matching runs after staging rather than
assuming packet-file order is chronological.

TCP timestamps refer to the frame where TShark completes the reassembled DNS
PDU. They are not an invented first-byte arrival time. Available reassembly
frame references are preserved as frame-level provenance, not asserted as a
separately reconstructed arrival timestamp for every coalesced PDU.

If only the first question of a multi-question packet is decodable, that
question can be preserved while missing questions are counted as exclusions.
Root queries are stored as `.`. Escaped names retain their textual representation
and an encoding flag; their textual measurements need downstream review.

## Response association

For ordinary DNS, association validates transport, stream, transaction ID,
client/server addresses and ports, timestamps, and available question details.

- Prefer TShark's `dns.response_to`, or the query's `dns.response_in` reference.
- Otherwise associate only a unique outstanding complete transaction/question.
- Do not make an arbitrary FIFO choice between several indistinguishable
  outstanding queries. Leave ambiguous observations unassigned.
- Retain original retransmission indicators and repeated-outstanding-query
  candidates. Retransmitted TCP segments are not extra application queries.
- Retain multiple explicitly associated replies and flag conflicting RCODEs;
  a conflicting result does not receive an invented single response code.
- Do not force unsolicited multicast replies into unicast one-to-one matching.

All observed response codes are preserved, including header codes and captured
OPT extended RCODE bits. If a response is truncated before an OPT record can be
decoded, its captured header code is explicitly marked
`header_only_extended_unknown`; it is not asserted to be a verified full EDNS
response code. Complete questions can still be extracted when answer sections
are incomplete.

Unmatched observations have blank response-code, response-time and latency
fields, plus explicit match status. A header association without a verified
question is distinguished from a question-verified association. An association
is not a security verdict or training label.

## Compatibility with the existing GRU schema

All legacy columns are retained. Added fields preserve transaction IDs,
transport/stream, question/PDU indexes, source hash, scope, association method,
response-frame references, retransmission provenance and incomplete-message flags.

Necessary downstream changes are deliberately **not** made to training code:

1. The old builder considers `(capture_path, packet_index)` unique. An adapter
   must use the composite identity before processing multi-question/PDU rows.
2. Decide whether to exclude multicast DNS and root/escaped-name observations;
   do not mix discovery traffic into an ordinary-DNS attack experiment by accident.
3. Preserve source category separately from reviewed session/query labels.
4. Review response confidence and extended response codes before enabling
   response features. Existing default M1 features do not use responses.
5. Preserve capture/session split boundaries and recompute features only after
   these provenance and label decisions.

This makes v2 an audited input for the **separate labelling/preparation stage**,
not permission to train a classifier on capture filenames. Most long attack
questions remain irrecoverable because their bytes were never captured.

## Run and validate

From the existing `DNSentinel` directory, these single-line commands work in
PowerShell or CMD:

```text
.\.venv\Scripts\python.exe -B -u prepare_gru_dataset_v2.py
.\.venv\Scripts\python.exe -B validate_extraction_v2.py
```

The default discovers the 14 PCAP files under the project raw directory. Output
must be empty; the script refuses to replace a prior extraction. For another
experiment, supply `--output-dir` with a fresh path and pass the same path to
the validator's `--directory` option.

Required outputs:

- `dns_observations.csv`: decoded question observations, never fabricated names.
- `extraction_audit.json`: per-capture/protocol counts, exclusions, settings,
  association methods, validation flags, schemas and hashes.
- `extraction_comparison.csv`: old/new counts, ordinary/multicast breakdown,
  responses and reasons for still-excluded questions.

Additional evidence includes `preservation_manifest.json`, per-pass stderr
logs, `validation_report.json` and `extraction_summary.md`. SQLite staging is
removed after a successful capture. Partial failures do not replace the old
processed dataset. Preliminary check outputs are separate from the final v2
directory and must not be concatenated with it.

## Protocol regression checks

```text
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_extraction_v2.py -v
```

The checks cover timestamp-regressed capture order, multiple/root questions,
TCP segmentation and multiple PDUs in one frame, numeric private types on a
reviewed nonstandard port, repeated queries, extended codes, truncated questions,
truncated answer sections and multicast response handling. Synthetic fixtures
are isolated and never added to production observations.

## Results of the completed 14-capture run

The validated run produced **110,148 question observations**: **84,835 ordinary DNS** and **25,313 separately tagged mDNS**. The ordinary-DNS counts are unchanged; the extra rows are real decoded multicast discovery questions, not newly reconstructed exfiltration payloads.

| Capture | Old | New total | Ordinary DNS | mDNS | DNS responses | Excluded ordinary questions |
|---|---:|---:|---:|---:|---:|---:|
| heavy_audio.pcap | 98 | 2306 | 98 | 2208 | 38171 | 38073 |
| heavy_compressed.pcap | 100 | 2480 | 100 | 2380 | 30672 | 30572 |
| heavy_exe.pcap | 112 | 2365 | 112 | 2253 | 40652 | 40545 |
| heavy_image.pcap | 90 | 2568 | 90 | 2478 | 42081 | 41991 |
| heavy_text.pcap | 223 | 4784 | 223 | 4561 | 27138 | 26919 |
| heavy_video.pcap | 136 | 2697 | 136 | 2561 | 44854 | 44788 |
| light_audio.pcap | 28 | 1155 | 28 | 1127 | 4322 | 4294 |
| light_compressed.pcap | 19 | 669 | 19 | 650 | 10085 | 10066 |
| light_exe.pcap | 13 | 419 | 13 | 406 | 6572 | 6559 |
| light_image.pcap | 0 | 25 | 0 | 25 | 489 | 489 |
| light_text.pcap | 8 | 186 | 8 | 178 | 2497 | 2489 |
| light_video.pcap | 8 | 284 | 8 | 276 | 4835 | 4827 |
| benign_1.pcap | 50594 | 54543 | 50594 | 3949 | 50135 | 11 |
| benign_2.pcap | 33406 | 35667 | 33406 | 2261 | 33415 | 29 |

The responses/excluded columns refer to ordinary DNS; multicast counts and exclusions remain separate in the audit. All ordinary excluded questions in this run were capture-truncated. Output counts are questions, not packets: several mDNS questions can share one message.

| Source category (not label) | Old ordinary DNS | New ordinary DNS | Additional mDNS | New total |
|---|---:|---:|---:|---:|
| Benign | 84,000 | 84,000 | 6,210 | 90,210 |
| Light attack | 76 | 76 | 2,662 | 2,738 |
| Heavy attack | 759 | 759 | 16,441 | 17,200 |
| Total | 84,835 | 84,835 | 25,313 | 110,148 |

All **2,024,996 packets** were audited. They contain no TCP frames, no decoded ordinary DNS outside port 53, and no complete DNS parse candidates among undecoded nonstandard UDP payloads. LLMNR accounts for 1,043,233 frames and mDNS for 69,434 frames. QUIC/UDP 443 traffic also exists; its presence is not a claim to have decrypted or ruled out encrypted DNS.

**Response association:** 83,716 question observations were associated: 29,202 using response-to references, 32,072 using response-in references, and 22,442 using unique validated transaction/question fallback. The remaining 26,432 rows are explicitly unmatched: 25,313 mDNS questions and 1,119 ordinary-DNS questions.

Compared with v1, 557 ordinary queries no longer receive an uncertain FIFO-attributed code; two previously unmatched queries gain validated TShark-reference associations. Where both versions assign a code, no associated code changed. Thus the net difference from v1 is 555 fewer assigned ordinary responses, not missing query extraction. Independently, chronological staging fixes the response-before-query file-order problem demonstrated by the protocol regression check; the two actual recovered associations are not claimed to prove that particular cause.

Validation passed: all 110,148 composite IDs are unique; question accounting equals TShark decoding; timestamps, source identities, ordering, schema and missingness checks pass; all 60 protected raw/source/model/previous-output hashes remain unchanged. Eight isolated protocol regression checks pass. TCP functionality is demonstrated by regression fixtures, not by recovered TCP records in this all-UDP dataset.

**Readiness:** suitable for the separate scope/provenance and labelling review stage. It is not a corrected attack training set: the 251,612 missing attack-capture ordinary questions remain unavailable, labels are unverified, and the existing GRU builder still needs a reviewed composite-key adapter for multiple questions/PDUs. No training or checkpoint change was performed.
