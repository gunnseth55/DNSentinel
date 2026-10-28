"""M1 shadow inference using the checkpoint's exact preprocessing."""
from collections import deque
from datetime import datetime, timezone

import numpy as np

from ml.common import require_torch
from ml.features import feature_schema, feature_vector, parent_domain, sequence_features, timestamp
from ml.gru_dataset import normalize


class M1Predictor:
    def __init__(self, checkpoint, device="cpu", non_overlapping=False, max_buffers=2048):
        self.torch = require_torch()
        from ml.gru_model import GRUModel
        saved = self.torch.load(checkpoint, map_location=device, weights_only=True)
        self.model = GRUModel(**saved["model_config"]).to(device)
        self.model.load_state_dict(saved["model_state_dict"])
        self.model.eval()
        self.device = device
        self.schema = saved["feature_schema"]
        self.normalization = saved["normalization"]
        self.threshold = saved["decision_threshold"]
        if self.threshold is None:
            raise ValueError("Checkpoint is incomplete; anomaly threshold has not been calibrated")
        self.version = saved["model_version"]
        expected = feature_schema(include_responses=self.schema["include_responses"])
        if (self.schema["schema_version"] != expected["schema_version"] or
                self.schema["feature_names"] != expected["feature_names"] or
                saved["model_config"]["input_size"] != len(expected["feature_names"]) or
                self.schema["group_by"] not in ("client", "client-parent")):
            raise ValueError("Checkpoint feature schema is incompatible with live features")
        if not np.isfinite(self.threshold):
            raise ValueError("Checkpoint threshold must be finite")
        self.non_overlapping = non_overlapping
        self.max_buffers = max_buffers
        self.buffers = {}
        self.last_activity = {}

    def predict(self, observations):
        from ml.gru_model import reconstruction_errors
        observations = list(observations)
        size = self.schema["sequence_length"]
        if not self.schema["min_length"] <= len(observations) <= size:
            raise ValueError("Need the checkpoint's configured sequence length/minimum")
        clients = {row["client_ip"] for row in observations}
        sessions = {(row.get("capture_path", ""), row.get("session_id", "")) for row in observations}
        if len(clients) != 1 or len(sessions) != 1:
            raise ValueError("Never combine clients or capture sessions in a prediction")
        if self.schema["group_by"] == "client-parent" and len({parent_domain(row) for row in observations}) != 1:
            raise ValueError("Checkpoint requires one parent-domain group per prediction")
        features = sequence_features(observations, self.schema)
        x = np.zeros((1, size, len(self.schema["feature_names"])), dtype=np.float32)
        x[0, :len(features)] = features
        lengths = np.asarray([len(features)], dtype=np.int64)
        x = normalize(x, lengths, self.normalization)
        warnings = []
        if any(row["qname"].lower().rstrip(".").endswith(".test") for row in observations):
            warnings.append("Reserved .test demo traffic differs from the Alexa-domain training reference.")
        changed_constants = [self.schema["feature_names"][i]
                             for i in self.normalization.get("constant_feature_indices", [])
                             if np.any(np.abs(x[0, :len(features), i]) > 1e-6)]
        if changed_constants:
            warnings.append("Features constant in training changed: " + ", ".join(changed_constants))
        if np.any(np.abs(x[0, :len(features), :6]) > 5):
            warnings.append("Some query features exceed five training standard deviations.")
        with self.torch.no_grad():
            values = self.torch.from_numpy(x).to(self.device)
            sizes = self.torch.from_numpy(lengths).to(self.device)
            output = self.model(values, sizes)
            if self.model.mode == "supervised":
                score = float(self.torch.sigmoid(output)[0].cpu())
            else:
                score = float(reconstruction_errors(output, values, sizes)[0].cpu())
        return {
            "detector": "M1", "mode": self.model.mode,
            "model_output": score,
            "score_kind": "reconstruction_error" if self.model.mode == "benign_autoencoder" else "uncalibrated_sigmoid_output",
            "decision_threshold": self.threshold,
            "exceeds_threshold": score >= self.threshold if self.model.mode == "supervised" else score > self.threshold,
            "model_version": self.version, "sequence_length": len(observations),
            "configured_sequence_length": size,
            "prediction_timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": observations[0]["client_ip"],
            "domains": sorted({row["qname"].lower().rstrip(".") for row in observations}),
            "parent_domains": sorted({parent_domain(row) or row["qname"].lower().rstrip(".")
                                      for row in observations}),
            "distribution_warnings": warnings,
            "interpretation": "Shadow-mode signal only; an anomaly is not proof of malicious traffic.",
        }

    def observe(self, observation):
        """Accept an ordered, completed observation; return None until a full window exists.

        Required keys: client_ip, qname, qtype_numeric and timestamp_monotonic_s
        (or timestamp_epoch_s). Timestamp must be captured when the query arrived,
        not when its response completed. Session IDs should change on restarts.
        Optional response features require explicit verified response provenance.
        """
        now = timestamp(observation)
        # Bound dormant client/session buffers without affecting gateway behaviour.
        for old_key in list(self.buffers):
            if now - self.last_activity[old_key] > self.schema["max_gap_s"]:
                del self.buffers[old_key]
                del self.last_activity[old_key]
        parent = parent_domain(observation) if self.schema["group_by"] == "client-parent" else ""
        key = (observation.get("capture_path", ""), observation.get("session_id", ""),
               observation["client_ip"], parent)
        previous = self.last_activity.get(key)
        if previous is not None and now < previous:
            raise ValueError("Observation arrival timestamps must be ordered within each client/session")
        feature_vector(observation, float(now - previous) if previous is not None else 0., self.schema["include_responses"])
        self.last_activity[key] = now
        if key not in self.buffers and len(self.buffers) >= self.max_buffers:
            oldest = min(self.buffers, key=self.last_activity.get)
            del self.buffers[oldest]
            del self.last_activity[oldest]
        buffer = self.buffers.setdefault(key, deque(maxlen=self.schema["sequence_length"]))
        buffer.append(dict(observation))
        if len(buffer) < self.schema["sequence_length"]:
            return None
        # Consume even a failed full window, so the worker can recover on the next one.
        window = list(buffer)
        if self.non_overlapping:
            buffer.clear()
        return self.predict(window)
