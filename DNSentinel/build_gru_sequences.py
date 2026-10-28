"""Build split-safe M1 sequences; does not train a model or rewrite the source CSV."""
import argparse
import csv
import json
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

import numpy as np

from ml.common import read_json, sha256, write_json
from ml.features import feature_schema, parent_domain, sequence_features, timestamp, truth
from ml.gru_dataset import fit_normalization


def validate_manifest(manifest, extraction_audit, mode):
    if manifest.get("schema_version") != 1 or manifest.get("mode") != mode:
        raise ValueError("Split manifest schema/mode does not match this build")
    if not manifest.get("evidence"):
        raise ValueError("Split manifest must document label/reference evidence")
    if mode == "supervised" and (manifest.get("label_scope") != "verified_query_or_session"
                                  or manifest.get("labels_verified") is not True):
        raise ValueError("Supervised mode requires explicit verified query/session labels, never capture categories")
    captures = {item["capture"]: item for item in extraction_audit["captures"]}
    if len(captures) != len(extraction_audit["captures"]):
        raise ValueError("Capture filenames must uniquely identify recordings in this dataset")
    capture_splits, sessions = {}, set()
    for segment in manifest["segments"]:
        name = segment["capture"]
        if name not in captures or segment["sha256"] != captures[name]["sha256"]:
            raise ValueError(f"Capture identity/hash mismatch: {name}")
        # V2 pins capture hashes in its validated output: do not reopen raw PCAPs.
        if extraction_audit.get("schema_version") != "dns-extraction-v2" and sha256(captures[name]["capture_path"]) != segment["sha256"]:
            raise ValueError(f"Raw capture changed since extraction: {name}")
        split, session = segment["split"], segment["session_id"]
        if split not in ("train", "validation", "test") or segment["label"] not in (0, 1):
            raise ValueError("Invalid split or binary label")
        if session in sessions:
            raise ValueError("Each manifest segment must have its own session_id")
        sessions.add(session)
        if name in capture_splits and capture_splits[name] != split:
            raise ValueError("The same recording cannot occur in multiple splits")
        capture_splits[name] = split
        if mode == "benign_autoencoder" and (segment["label"] != 0 or captures[name]["capture_group"] != "benign"):
            raise ValueError("Benign autoencoder accepts only the publisher's benign reference recordings")
        start, end = segment.get("start_epoch_s"), segment.get("end_epoch_s")
        if (start is None) != (end is None):
            raise ValueError("Both interval bounds must be provided, or neither")
        if start is not None and not Decimal(str(start)) < Decimal(str(end)):
            raise ValueError("Label interval must be increasing, with exclusive upper bound")
        if mode == "supervised" and (segment.get("verified") is not True or not segment.get("evidence")):
            raise ValueError("Every supervised session needs verified=true and explicit evidence")
    required = {"train", "validation", "test"} if mode == "supervised" else {"train", "validation"}
    if not required <= set(capture_splits.values()):
        raise ValueError("Independent captures are required for every requested split: " + ", ".join(sorted(required)))
    return captures


def observation_identity(row, version_two):
    if not version_two:
        return row["capture_path"], row["packet_index"]
    expected = ":".join(row[name] for name in ("capture_sha256", "packet_index", "dns_message_index", "question_index"))
    if row.get("observation_id") != expected:
        raise ValueError("Invalid v2 composite observation identity")
    return expected


def build(args):
    if not 1 <= args.min_length <= args.sequence_length or args.stride < args.sequence_length:
        raise ValueError("Require 1 <= min-length <= sequence-length and stride >= sequence-length (no overlap)")
    if not np.isfinite(args.max_gap_s) or args.max_gap_s <= 0:
        raise ValueError("max-gap-s must be positive and finite")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise ValueError("Output directory is not empty; use a new directory to preserve prior datasets")
    manifest = read_json(args.split_manifest)
    extraction = read_json(args.extraction_audit)
    version_two = extraction.get("schema_version") == "dns-extraction-v2"
    if version_two:
        if extraction.get("status") != "completed" or sha256(args.input) != extraction.get("output_csv_sha256"):
            raise ValueError("V2 CSV hash/completion does not match its extraction audit")
    captures = validate_manifest(manifest, extraction, args.mode)
    schema = feature_schema(args.sequence_length, args.min_length, args.group_by,
                            args.max_gap_s, args.include_responses)
    groups, seen, source_counts = defaultdict(list), set(), Counter()
    ignored = 0
    scope_exclusions = Counter()
    with args.input.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        required = {"capture", "capture_path", "client_ip", "qname", "qtype_numeric",
                    "timestamp_epoch_s", "packet_index"}
        if not required <= set(reader.fieldnames or []):
            raise ValueError(f"Missing CSV columns: {sorted(required - set(reader.fieldnames or []))}")
        for row in reader:
            stamp = timestamp(row)
            identity = observation_identity(row, version_two)
            if identity in seen:
                raise ValueError("Repeated capture/packet identity in the CSV")
            seen.add(identity)
            if version_two:
                if row.get("dns_scope") != "unicast_dns":
                    scope_exclusions["multicast_or_other_scope"] += 1
                    continue
                if row.get("qname_encoding") != "text" or row["qname"] == ".":
                    scope_exclusions["root_or_escaped_qname_not_supported_by_live_features"] += 1
                    continue
                if row.get("question_count") != "1":
                    scope_exclusions["multi_question_message_not_accepted_by_live_gateway"] += 1
                    continue
                if args.include_responses:
                    # Keep source response values unchanged; mask unsupported or
                    # uncertain associations only in the model's feature view.
                    reliable = (truth(row.get("response_question_verified")) and
                                not truth(row.get("response_timing_ambiguous")) and
                                not truth(row.get("response_code_conflict")) and
                                row.get("response_code_scope") in ("header_complete", "header_plus_opt_extended") and
                                row.get("response_code_numeric", "") != "" and
                                0 <= int(row["response_code_numeric"]) <= 15)
                    if not reliable:
                        row["response_matched"] = False
                        row["response_question_verified"] = False
            matches = []
            for segment in manifest["segments"]:
                if row["capture"] != segment["capture"]:
                    continue
                if row["capture_path"] != captures[row["capture"]]["capture_path"]:
                    raise ValueError("CSV capture path differs from its extraction audit")
                if segment.get("client_ip") and segment["client_ip"] != row["client_ip"]:
                    continue
                if segment.get("start_epoch_s") is not None:
                    if not Decimal(str(segment["start_epoch_s"])) <= stamp < Decimal(str(segment["end_epoch_s"])):
                        continue
                matches.append(segment)
            if len(matches) > 1:
                raise ValueError("Overlapping label sessions assign the same query twice")
            if not matches:
                ignored += 1
                continue
            segment = matches[0]
            parent = parent_domain(row) if args.group_by == "client-parent" else ""
            key = (segment["split"], segment["session_id"], row["capture"], row["client_ip"], parent, segment["label"])
            groups[key].append(row)
            source_counts[row["capture"]] += 1
    arrays = {split: [] for split in ("train", "validation", "test")}
    lengths, labels, metadata = ({split: [] for split in arrays} for _ in range(3))
    dropped = Counter()
    used_rows = set()
    for key, observations in sorted(groups.items()):
        split, session, capture, client, parent, label = key
        observations.sort(key=lambda row: (timestamp(row), int(row["packet_index"]),
                                           int(row.get("dns_message_index", 1)), int(row.get("question_index", 1))))
        blocks, current, previous = [], [], None
        for row in observations:
            stamp = timestamp(row)
            if previous is not None and float(stamp - previous) > args.max_gap_s:
                blocks.append(current)
                current = []
            current.append(row)
            previous = stamp
        if current:
            blocks.append(current)
        for block_index, block in enumerate(blocks):
            for offset in range(0, len(block), args.stride):
                chunk = block[offset:offset + args.sequence_length]
                if len(chunk) < args.min_length:
                    dropped[split] += len(chunk)
                    continue
                features = sequence_features(chunk, schema)
                padded = np.zeros((args.sequence_length, len(schema["feature_names"])), dtype=np.float32)
                padded[:len(chunk)] = features
                for row in chunk:
                    identity = observation_identity(row, version_two)
                    if identity in used_rows:
                        raise ValueError("Query reuse/overlap across sequence windows")
                    used_rows.add(identity)
                arrays[split].append(padded)
                lengths[split].append(len(chunk))
                labels[split].append(label)
                metadata[split].append({
                    "sequence_id": f"{session}:{client}:{parent}:{block_index}:{offset}",
                    "capture": capture, "session_id": session, "client_ip": client,
                    "parent_domain": parent, "split": split, "label": label,
                    "start_epoch_s": chunk[0]["timestamp_epoch_s"],
                    "end_epoch_s": chunk[-1]["timestamp_epoch_s"],
                    "packet_indices": [int(row["packet_index"]) for row in chunk],
                    "observation_ids": [row["observation_id"] for row in chunk] if version_two else [],
                    "length": len(chunk),
                })
    for split in (("train", "validation", "test") if args.mode == "supervised" else ("train", "validation")):
        if not arrays[split]:
            raise ValueError(f"No {split} sequences. Check session gaps, min-length and label coverage")
        if args.mode == "supervised" and set(labels[split]) != {0, 1}:
            raise ValueError(f"Supervised {split} needs both verified classes from held-out captures")
    if args.mode == "supervised" and args.min_length < args.sequence_length:
        # Do not permit padding amount to identify the class.
        for split in ("train", "validation", "test"):
            if not labels[split]:
                continue
            distributions = {value: Counter(length for length, target in zip(lengths[split], labels[split]) if target == value)
                             for value in (0, 1)}
            totals = {value: sum(distributions[value].values()) for value in (0, 1)}
            if not all(totals.values()) or any(
                distributions[0][length] * totals[1] != distributions[1][length] * totals[0]
                for length in set(distributions[0]) | set(distributions[1])
            ):
                raise ValueError(f"{split}: class-dependent sequence lengths. Use full-length windows or construct length-matched verified sessions")
    width = len(schema["feature_names"])
    data = {split: np.stack(values) if values else np.zeros((0, args.sequence_length, width), np.float32)
            for split, values in arrays.items()}
    normalizer = fit_normalization(data["train"], np.asarray(lengths["train"]))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    files = {}
    for split in arrays:
        target = args.output_dir / f"{split}.npz"
        np.savez_compressed(target, X=data[split], lengths=np.asarray(lengths[split], dtype=np.int64),
                            y=np.asarray(labels[split], dtype=np.float32))
        with (args.output_dir / f"{split}_metadata.jsonl").open("w", encoding="utf-8") as stream:
            for row in metadata[split]:
                stream.write(json.dumps(row) + "\n")
        files[split] = {"file": target.name, "sha256": sha256(target), "sequences": len(data[split]),
                        "class_counts": dict(Counter(labels[split])), "length_counts": dict(Counter(lengths[split]))}
    write_json(args.output_dir / "feature_schema.json", schema)
    write_json(args.output_dir / "normalization.json", normalizer)
    write_json(args.output_dir / "split_manifest.json", manifest)
    prepared = {
        "mode": args.mode, "seed": args.seed, "source_csv": str(args.input.resolve()),
        "source_csv_sha256": sha256(args.input), "extraction_audit_sha256": sha256(args.extraction_audit),
        "split_manifest_sha256": sha256(args.split_manifest), "feature_schema": schema,
        "normalization_fit_split": "train", "normalization_valid_tokens": int(sum(lengths["train"])),
        "source_extraction_version": "v2" if version_two else "v1",
        "scope_exclusions": dict(scope_exclusions),
        "preprocessing_files": {filename: sha256(args.output_dir / filename) for filename in
                                ("feature_schema.json", "normalization.json", "split_manifest.json")},
        "metadata_files": {split: sha256(args.output_dir / f"{split}_metadata.jsonl") for split in arrays},
        "capture_rows_selected": dict(source_counts), "unlabelled_or_unselected_rows_excluded": ignored,
        "short_tail_rows_dropped": dict(dropped), "stride": args.stride, "splits": files,
        "limitations": ["Benign-reference autoencoder validation is not attack classification evaluation.",
                        "Response features default OFF; capture loss and repeated queries remain dataset limitations.",
                        "No random record split, overlapping windows, provenance inputs or padding in the default configuration.",
                        "Source CSV response associations are preserved and are not repaired by sorting queries."],
    }
    write_json(args.output_dir / "dataset_manifest.json", prepared)
    print(json.dumps({"mode": args.mode, "features": width, "sequence_length": args.sequence_length,
                      "splits": {split: len(data[split]) for split in data}}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("data/cic_bell_exf_2021/processed/all_captures/dns_observations.csv"))
    parser.add_argument("--extraction-audit", type=Path, default=Path("data/cic_bell_exf_2021/processed/all_captures/extraction_audit.json"))
    parser.add_argument("--split-manifest", type=Path, default=Path("configs/m1_benign_split.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("models/gru/prepared_benign"))
    parser.add_argument("--mode", choices=("benign_autoencoder", "supervised"), default="benign_autoencoder")
    parser.add_argument("--sequence-length", type=int, default=20)
    parser.add_argument("--min-length", type=int)
    parser.add_argument("--stride", type=int)
    parser.add_argument("--group-by", choices=("client", "client-parent"), default="client")
    parser.add_argument("--max-gap-s", type=float, default=300)
    parser.add_argument("--include-responses", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    args.min_length = args.sequence_length if args.min_length is None else args.min_length
    args.stride = args.sequence_length if args.stride is None else args.stride
    try:
        build(args)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f"Sequence preparation failed: {error}\n")


if __name__ == "__main__":
    main()
