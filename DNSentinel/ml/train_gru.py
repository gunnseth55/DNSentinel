"""Reproducible CPU-first M1 training. Only starts when explicitly run."""
import argparse
import csv
import os
import random
import shutil
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from ml.common import read_json, require_torch, write_json
from ml.gru_dataset import DNSSequenceDataset


def run(args):
    if args.epochs < 1 or args.batch_size < 1 or args.hidden_size < 1 or args.patience < 1 or args.cpu_threads < 1:
        raise ValueError("Epochs, batch size, hidden size and patience must be positive")
    if not 0 <= args.dropout < 1 or not 0 < args.threshold_quantile < 1:
        raise ValueError("Invalid dropout or anomaly threshold quantile")
    if not 0 < args.learning_rate < float("inf") or not 0 <= args.weight_decay < float("inf"):
        raise ValueError("Invalid learning rate or weight decay")
    if not 0 <= args.min_delta < float("inf"):
        raise ValueError("min-delta must be finite and nonnegative")
    torch = require_torch()
    from torch.utils.data import DataLoader
    from ml.gru_model import GRUModel, reconstruction_errors
    from ml.evaluate_gru import binary_metrics, predict_dataset, score_summary
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(args.seed)
    torch.use_deterministic_algorithms(True)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True
    torch.set_num_threads(args.cpu_threads)
    if args.device == "auto":
        args.device = "cuda" if torch.cuda.is_available() else "cpu"
    if args.device == "cuda" and not torch.cuda.is_available():
        raise ValueError("CUDA requested but not available; use --device cpu")
    manifest = read_json(args.data / "dataset_manifest.json")
    schema = read_json(args.data / "feature_schema.json")
    normalization = read_json(args.data / "normalization.json")
    if schema != manifest["feature_schema"] or normalization.get("fit_split") != "train":
        raise ValueError("Feature schema or training-only normalization mismatch")
    train = DNSSequenceDataset(args.data, "train", normalization)
    validation = DNSSequenceDataset(args.data, "validation", normalization)
    mode = manifest["mode"]
    if not len(train) or not len(validation):
        raise ValueError("Training and validation datasets must be nonempty")
    if mode == "supervised" and (set(train.y.tolist()) != {0., 1.} or set(validation.y.tolist()) != {0., 1.}):
        raise ValueError("Verified supervised training/validation must contain both classes")
    if mode == "benign_autoencoder" and ((train.y != 0).any() or (validation.y != 0).any()):
        raise ValueError("Autoencoder splits must contain only benign reference observations")
    config = {"input_size": len(schema["feature_names"]), "hidden_size": args.hidden_size,
              "dropout": args.dropout, "mode": mode}
    model = GRUModel(**config).to(args.device)
    generator = torch.Generator().manual_seed(args.seed)
    train_loader = DataLoader(train, batch_size=args.batch_size, shuffle=True,
                              num_workers=0, generator=generator)
    val_loader = DataLoader(validation, batch_size=args.batch_size, shuffle=False, num_workers=0)
    if args.smoke_only:
        batch = next(iter(val_loader))
        with torch.no_grad():
            model.eval()
            result = model(batch["x"].to(args.device), batch["length"].to(args.device))
        if not torch.isfinite(result).all():
            raise ValueError("Forward pass produced nonfinite values")
        print(f"Forward smoke check passed: {tuple(batch['x'].shape)} -> {tuple(result.shape)}; no training performed")
        return
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError("Run output is not empty; use a new run folder to preserve previous experiments")
    args.output.mkdir(parents=True, exist_ok=True)
    version = "M1-" + mode + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    experiment = dict(vars(args))
    experiment = {key: str(value) if isinstance(value, Path) else value for key, value in experiment.items()}
    experiment.update(model_config=config, model_version=version, torch_version=str(torch.__version__),
                      numpy_version=np.__version__, deterministic_algorithms=True,
                      device_used=args.device,
                      validation_limitation="Held-out capture used for early stopping, not an independent final test.")
    write_json(args.output / "model_config.json", experiment)
    for filename in ("dataset_manifest.json", "split_manifest.json", "feature_schema.json", "normalization.json"):
        shutil.copyfile(args.data / filename, args.output / filename)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate, weight_decay=args.weight_decay)
    positive_weight = float((train.y == 0).sum() / (train.y == 1).sum()) if mode == "supervised" else None
    criterion = (torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor(positive_weight, device=args.device), reduction="none")
                 if mode == "supervised" else None)

    def epoch_loss(loader, training):
        model.train(training)
        total, count = 0., 0
        with torch.set_grad_enabled(training):
            for batch in loader:
                x, lengths, y = batch["x"].to(args.device), batch["length"].to(args.device), batch["y"].to(args.device)
                if training:
                    optimizer.zero_grad(set_to_none=True)
                prediction = model(x, lengths)
                loss = (criterion(prediction, y) if mode == "supervised"
                        else reconstruction_errors(prediction, x, lengths)).mean()
                if not torch.isfinite(loss):
                    raise ValueError("Training/validation loss became nonfinite")
                if training:
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                    optimizer.step()
                total += float(loss.detach()) * len(x)
                count += len(x)
        return total / count

    best, stale, best_epoch = float("inf"), 0, 0
    checkpoint = args.output / "best.pt"
    with (args.output / "training_history.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["epoch", "train_loss", "validation_loss"])
        writer.writeheader()
        for epoch in range(1, args.epochs + 1):
            training_loss = epoch_loss(train_loader, True)
            validation_loss = epoch_loss(val_loader, False)
            writer.writerow({"epoch": epoch, "train_loss": training_loss, "validation_loss": validation_loss})
            stream.flush()
            print(f"Epoch {epoch:02d}/{args.epochs}: train_loss={training_loss:.8f} validation_loss={validation_loss:.8f}", flush=True)
            if validation_loss < best - args.min_delta:
                best, stale, best_epoch = validation_loss, 0, epoch
                torch.save({"model_state_dict": model.state_dict(), "model_config": config,
                            "feature_schema": schema, "normalization": normalization,
                            "dataset_manifest": manifest, "model_version": version,
                            "best_epoch": epoch, "decision_threshold": None}, checkpoint)
            else:
                stale += 1
                if stale >= args.patience:
                    print("Early stopping", flush=True)
                    break
    saved = torch.load(checkpoint, map_location=args.device, weights_only=True)
    model.load_state_dict(saved["model_state_dict"])
    train_scores, _ = predict_dataset(model, train, args.device, args.batch_size)
    validation_scores, validation_labels = predict_dataset(model, validation, args.device, args.batch_size)
    metrics = {"mode": mode, "best_epoch": best_epoch, "best_validation_loss": best,
               "model_version": version, "training_positive_weight": positive_weight,
               "classification_metrics_available": mode == "supervised"}
    if mode == "supervised":
        saved["decision_threshold"] = .5
        metrics["validation"] = binary_metrics(validation_labels, validation_scores)
    else:
        threshold = float(np.quantile(train_scores, args.threshold_quantile))
        saved["decision_threshold"] = threshold
        metrics.update(threshold_quantile=args.threshold_quantile, threshold_fit_split="train",
                       decision_threshold=threshold, training=score_summary(train_scores),
                       validation=score_summary(validation_scores),
                       validation_benign_threshold_exceedance_rate=float((validation_scores > threshold).mean()),
                       interpretation="Reconstruction loss and benign exceedance rate do not establish malicious-traffic detection accuracy.")
    torch.save(saved, checkpoint)
    write_json(args.output / "evaluation_metrics.json", metrics)
    print(f"Saved best checkpoint: {checkpoint}\nMetrics: {metrics}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("models/gru/prepared_benign"))
    parser.add_argument("--output", type=Path, default=Path("models/gru/m1_benign_ae"))
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--hidden-size", type=int, default=32)
    parser.add_argument("--dropout", type=float, default=.1)
    parser.add_argument("--learning-rate", type=float, default=.001)
    parser.add_argument("--weight-decay", type=float, default=.0001)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--min-delta", type=float, default=.00001)
    parser.add_argument("--threshold-quantile", type=float, default=.99)
    parser.add_argument("--device", choices=("cpu", "cuda", "auto"), default="cpu")
    parser.add_argument("--cpu-threads", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--smoke-only", action="store_true")
    args = parser.parse_args()
    try:
        run(args)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f"M1 training failed: {error}\n")


if __name__ == "__main__":
    main()
