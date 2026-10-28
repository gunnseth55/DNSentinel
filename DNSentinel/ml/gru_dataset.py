"""NumPy preprocessing and a DataLoader-compatible dataset; no torch import needed."""
from pathlib import Path

import numpy as np

from ml.common import read_json, sha256


def valid_mask(lengths, width):
    return np.arange(width)[None, :] < np.asarray(lengths)[:, None]


def fit_normalization(x, lengths):
    tokens = x[valid_mask(lengths, x.shape[1])].astype(np.float64)
    if not len(tokens) or not np.isfinite(tokens).all():
        raise ValueError("Training features must be finite and nonempty")
    mean, std = tokens.mean(axis=0), tokens.std(axis=0)
    constant = std < 1e-8
    std[constant] = 1.0
    return {"mean": mean.tolist(), "std": std.tolist(), "constant_feature_indices": np.flatnonzero(constant).tolist(),
            "fit_split": "train", "fit_tokens": len(tokens), "padding_excluded": True}


def normalize(x, lengths, normalizer):
    mean, std = np.asarray(normalizer["mean"]), np.asarray(normalizer["std"])
    if len(mean) != x.shape[-1] or len(std) != len(mean) or not np.isfinite(std).all() or (std <= 0).any():
        raise ValueError("Normalization/schema mismatch")
    result = ((x - mean) / std).astype(np.float32)
    result[~valid_mask(lengths, x.shape[1])] = 0.0
    if not np.isfinite(result).all():
        raise ValueError("Normalization produced nonfinite values")
    return result


class DNSSequenceDataset:
    def __init__(self, directory, split, normalizer=None):
        directory = Path(directory)
        manifest = read_json(directory / "dataset_manifest.json")
        for filename, digest in manifest.get("preprocessing_files", {}).items():
            if sha256(directory / filename) != digest:
                raise ValueError(f"Prepared preprocessing file changed: {filename}")
        if split in manifest.get("metadata_files", {}):
            if sha256(directory / f"{split}_metadata.jsonl") != manifest["metadata_files"][split]:
                raise ValueError(f"Prepared sequence metadata changed: {split}")
        entry = manifest["splits"][split]
        path = directory / entry["file"]
        if sha256(path) != entry["sha256"]:
            raise ValueError(f"Prepared {split} file changed since its manifest was written")
        with np.load(path, allow_pickle=False) as data:
            self.x, self.lengths, self.y = data["X"], data["lengths"], data["y"]
        schema = manifest["feature_schema"]
        if self.x.ndim != 3 or self.x.shape[1:] != (schema["sequence_length"], len(schema["feature_names"])):
            raise ValueError("Sequence tensor/schema mismatch")
        if self.lengths.shape != (len(self.x),) or self.y.shape != (len(self.x),):
            raise ValueError("Invalid sequence lengths/targets")
        if (self.lengths < 1).any() or (self.lengths > self.x.shape[1]).any():
            raise ValueError("Invalid packed sequence lengths")
        self.x = normalize(self.x, self.lengths, normalizer or read_json(directory / "normalization.json"))

    def __len__(self):
        return len(self.x)

    def __getitem__(self, index):
        return {"x": self.x[index], "length": self.lengths[index], "y": self.y[index]}
