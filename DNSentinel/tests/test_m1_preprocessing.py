"""Preprocessing checks only: no torch dependency, training or gateway changes."""
import unittest
from unittest.mock import patch

import numpy as np

from build_gru_sequences import validate_manifest
from ml.evaluate_gru import binary_metrics
from ml.features import feature_schema, feature_vector, sequence_features
from ml.gru_dataset import fit_normalization, normalize


class TestM1Preprocessing(unittest.TestCase):
    def observation(self, **changes):
        return {"qname": "a1.demo.test", "qtype_numeric": "1", "timestamp_epoch_s": "10.0", **changes}

    def test_features_exclude_source_identity(self):
        first = feature_vector(self.observation(), 0)
        second = feature_vector(self.observation(capture_group="attack_heavy", capture="bad.pcap", client_ip="10.0.0.5"), 0)
        np.testing.assert_array_equal(first, second)
        self.assertEqual(len(first), 12)
        self.assertEqual(first[3], .5)

    def test_unknown_response_is_not_noerror(self):
        missing = feature_vector(self.observation(response_code_numeric="0"), 0, True)
        explicit = feature_vector(self.observation(response_code_numeric="0", response_matched=True), 0, True)
        self.assertEqual(missing[12:].sum(), 0)
        self.assertEqual(explicit[12], 1)
        self.assertEqual(explicit[13], 1)
        ambiguous = feature_vector(self.observation(response_code_numeric="0", response_matched=True,
                                                   response_timing_ambiguous=True), 0, True)
        self.assertEqual(ambiguous[12:].sum(), 0)

    def test_numeric_private_types_and_parent_depth(self):
        values = feature_vector(self.observation(qname="x.a.example.co.uk", qtype_numeric="65534"), 0)
        self.assertEqual(values[4], 2)
        self.assertEqual(values[10], 1)

    def test_sequence_order_and_session_gap(self):
        schema = feature_schema()
        with self.assertRaises(ValueError):
            sequence_features([self.observation(), self.observation(timestamp_epoch_s="9")], schema)
        with self.assertRaises(ValueError):
            sequence_features([self.observation(), self.observation(timestamp_epoch_s="400")], schema)

    def test_padding_excluded_from_training_normalization(self):
        x = np.asarray([[[2., 1.], [4., 1.], [999., 999.]]], np.float32)
        normalizer = fit_normalization(x, np.asarray([2]))
        np.testing.assert_allclose(normalizer["mean"], [3, 1])
        transformed = normalize(x, np.asarray([2]), normalizer)
        np.testing.assert_array_equal(transformed[0, 2], [0, 0])

    def test_supervised_rejects_unverified_labels(self):
        with self.assertRaises(ValueError):
            validate_manifest({"schema_version": 1, "mode": "supervised", "evidence": "folder names",
                               "label_scope": "capture_group", "segments": []}, {"captures": []}, "supervised")

    def test_confusion_matrix(self):
        result = binary_metrics([0, 0, 1, 1], [.1, .8, .7, .2])
        self.assertEqual(result["confusion_matrix"], {"TN": 1, "FP": 1, "FN": 1, "TP": 1})
        self.assertEqual(result["f1"], .5)

    def test_capture_cannot_leak_across_splits(self):
        manifest = {"schema_version": 1, "mode": "benign_autoencoder", "evidence": "reference",
                    "segments": [
                        {"capture": "one.pcap", "sha256": "raw", "session_id": "one", "label": 0, "split": "train"},
                        {"capture": "one.pcap", "sha256": "raw", "session_id": "two", "label": 0, "split": "validation"},
                    ]}
        audit = {"captures": [{"capture": "one.pcap", "sha256": "raw", "capture_path": "not_opened",
                               "capture_group": "benign"}]}
        with patch("build_gru_sequences.sha256", return_value="raw"):
            with self.assertRaisesRegex(ValueError, "same recording"):
                validate_manifest(manifest, audit, "benign_autoencoder")


if __name__ == "__main__":
    unittest.main()
