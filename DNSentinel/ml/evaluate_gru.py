"""Evaluate saved M1 checkpoints without inventing labels or classification metrics."""
import argparse
from pathlib import Path

import numpy as np

from ml.common import read_json, require_torch, write_json
from ml.gru_dataset import DNSSequenceDataset


def binary_metrics(targets, scores, threshold=0.5):
    labels = np.asarray(targets)
    if not np.isin(labels, (0, 1)).all():
        raise ValueError("Binary metrics require verified binary labels")
    labels = labels.astype(np.int64)
    if not np.isfinite(scores).all() or len(labels) != len(scores):
        raise ValueError("Scores must be finite and align with targets")
    predictions = np.asarray(scores) >= threshold
    tp = int(((labels == 1) & predictions).sum())
    fp = int(((labels == 0) & predictions).sum())
    tn = int(((labels == 0) & ~predictions).sum())
    fn = int(((labels == 1) & ~predictions).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "confusion_matrix": {"TN": tn, "FP": fp, "FN": fn, "TP": tp},
        "class_distribution": {"benign": int((labels == 0).sum()), "attack": int((labels == 1).sum())},
        "decision_threshold": threshold,
    }


def predict_dataset(model, dataset, device="cpu", batch_size=128):
    torch = require_torch()
    from torch.utils.data import DataLoader
    from ml.gru_model import reconstruction_errors
    model.eval()
    outputs, targets = [], []
    with torch.no_grad():
        for batch in DataLoader(dataset, batch_size=batch_size, shuffle=False, num_workers=0):
            x, lengths = batch["x"].to(device), batch["length"].to(device)
            prediction = model(x, lengths)
            score = (torch.sigmoid(prediction) if model.mode == "supervised"
                     else reconstruction_errors(prediction, x, lengths))
            outputs.extend(score.cpu().tolist())
            targets.extend(batch["y"].tolist())
    if not outputs:
        raise ValueError("Cannot evaluate an empty split")
    return np.asarray(outputs), np.asarray(targets)


def score_summary(scores):
    return {"sequences": len(scores), "mean_reconstruction_error": float(np.mean(scores)),
            "std_reconstruction_error": float(np.std(scores)),
            "error_quantiles": {str(q): float(np.quantile(scores, q)) for q in (.5, .9, .95, .99)}}


def evaluate(checkpoint, dataset, split, device="cpu"):
    torch = require_torch()
    from ml.gru_model import GRUModel
    saved = torch.load(checkpoint, map_location=device, weights_only=True)
    manifest = read_json(Path(dataset) / "dataset_manifest.json")
    if manifest != saved["dataset_manifest"]:
        raise ValueError("Evaluation dataset differs from checkpoint manifest")
    data = DNSSequenceDataset(dataset, split, saved["normalization"])
    model = GRUModel(**saved["model_config"]).to(device)
    model.load_state_dict(saved["model_state_dict"])
    scores, labels = predict_dataset(model, data, device)
    result = {"mode": model.mode, "split": split, "model_version": saved["model_version"]}
    if model.mode == "supervised":
        result.update(binary_metrics(labels, scores, saved["decision_threshold"]))
    else:
        result.update(score_summary(scores))
        threshold = saved["decision_threshold"]
        result.update(decision_threshold=threshold,
                      benign_threshold_exceedance_rate=float((scores > threshold).mean()),
                      threshold_basis="Training reconstruction errors only; not a malicious-traffic classifier.",
                      classification_precision=None, classification_recall=None, classification_f1=None)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--split", choices=("validation", "test"), default="validation")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate(args.checkpoint, args.data, args.split, args.device)
    output = args.output or args.checkpoint.parent / f"{args.split}_metrics.json"
    write_json(output, result)
    print(result)


if __name__ == "__main__":
    main()
