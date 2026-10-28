# M1 GRU pipeline: first benign-reference model trained

The user completed the forward smoke check and the first 10-epoch CPU training run on 28 October 2026. The saved model is a **benign-reference GRU sequence autoencoder**, not a trained supervised attack classifier. PyTorch is installed; the checkpoint, actual losses and reconstruction metrics are available under `models/gru/m1_benign_ae/`.

The main [project README](README.md#5-m1-implementation-and-completed-first-training-run) records the complete epoch table, configuration, audit findings and interpretation. This guide documents the pipeline and commands. The live DNS gateway and B0/B1/P1 were not modified for M1.

## Recorded training result

| Epoch | Training loss | Validation loss |
|---|---:|---:|
| 1 | 0.50269618 | 0.51217056 |
| 2 | 0.49778037 | 0.51123715 |
| 3 | 0.49614463 | 0.50804029 |
| 4 | 0.49176763 | 0.49475973 |
| 5 | 0.47764524 | 0.48607982 |
| 6 | 0.47024178 | 0.47607797 |
| 7 | 0.46360446 | 0.46859546 |
| 8 | 0.46085591 | 0.46717381 |
| 9 | 0.45898320 | 0.46418311 |
| 10 | 0.45653193 | 0.46097860 |

- Best epoch: **10**; best validation loss: **0.46097860**.
- Mean reconstruction error: training **0.45342292**, validation **0.46097860**.
- Training-only 99th-percentile threshold: **1.16123543**.
- Validation exceedances: **8/1670 (0.47904%)**.
- Checkpoint: [`models/gru/m1_benign_ae/best.pt`](models/gru/m1_benign_ae/best.pt).
- Model version: `M1-benign_autoencoder-20261028T142050413090Z`.
- Recorded packages: PyTorch **2.15.0+cpu**, NumPy **2.5.4**.
- Forward smoke check: **(64, 20, 12) -> (64, 20, 12)**, passed before training.

These are reconstruction statistics and benign false-alarm candidates. Attack precision/recall/F1 and independent test accuracy have not been measured.

`models/gru/preparation_status.json` and `planned_experiment.json` remain historical preparation snapshots. Use the saved run's configuration, history and metrics as the record of completed training.

## Audit and experiment choice

Original input files are preserved:

- `data/cic_bell_exf_2021/processed/all_captures/dns_observations.csv`
- `data/cic_bell_exf_2021/processed/all_captures/extraction_audit.json`

The independent audit is `models/gru/dataset_audit.json`. It checks source
SHA-256 identities, timestamps, missing responses, outstanding repeated queries,
and TShark's two-pass DNS dissection/linkage for all 14 raw files. Reproduce it:

```powershell
.\.venv\Scripts\python.exe -B -m ml.audit_dns_dataset
```

Verified source-category counts: 84,000 benign-capture, 76 light-capture, and
759 heavy-capture observations (84,835 total). These are not class labels.
The attack recordings contain 252,447 UDP/53 queries; 251,612 lack complete
questions in 96-byte truncated packets. `light_image.pcap` contains 489 queries,
all incomplete. TShark found no additional complete questions missing from the
CSV and no recognized DNS outside UDP/53 in these captures. This does not rule
out arbitrary concealed/encrypted DNS on other ports. Missing bytes cannot be
recovered by a parser change.

The CSV has 564 missing responses, 23,550 repeated-outstanding-query rows and
46,087 ambiguous response timing rows. Missing responses remain unknown, never
assumed NXDOMAIN or NOERROR. Python matches 50,124 queries in `benign_1.pcap`;
TShark's `dns.response_to` references 15,561 distinct queries. These different
association semantics are reported, not silently substituted. Original FIFO
associations and retransmission rows are preserved. The original extractor also
matches before chronological sorting: timestamp regressions can cause missed
matches. M1's default inputs exclude response fields and response latency.

The publisher describes benign recordings, an exfiltration domain and attack
clock schedules. Local files contain neither timezone-verified per-query truth
nor an independent packet label table. The attack recordings contain background
DNS traffic, so assigning their entire contents the attack label is unjustified.
Of 53 distinct QNAMEs recovered from the attack recordings, most are background
service names. One recovered query ends in the publisher's exfiltration domain,
`cicresearch.ca`; that is a candidate for label investigation, not enough data to
establish representative attack sequences or justify labelling the other queries.
The selected experiment is therefore a **benign-reference GRU autoencoder**,
using the publisher-designated benign files as a reference assumption rather
than claiming independently verified per-query benignness.

Source: https://www.unb.ca/cic/datasets/dns-exf-2021.html

Dataset citation: Samaneh Mahdavifar, Amgad Hanafy Salem, Princy Victor,
Miguel Garzon, Amir H. Razavi, Natasha Hellberg, and Arash Habibi Lashkari,
“Lightweight Hybrid Detection of Data Exfiltration using DNS based on Machine
Learning,” ICCNS, 2021.

## Features and sequences

Default input is **20 queries × 12 numerical features**:

1. Leftmost label length.
2. Full normalized QNAME length (without trailing dot).
3. Leftmost label Shannon entropy, reusing P1's entropy implementation.
4. Leftmost label digit ratio.
5. Number of subdomain labels below the registered domain, reusing P1's offline
   `tldextract` instance (including `.test` and multipart public suffixes).
6. `log1p` of the previous query gap, with the first query in every window set to zero.
7–12. Fixed one-hot query type: A, AAAA, TXT, NULL, private-use 65280–65534, other.

Capture name/category, client/server IPs, absolute timestamps, actual domain
identities, padding flags, packet truncation and retransmission flags are not
features. Metadata is saved separately as JSONL. The 12-feature schema supersedes
the earlier provisional 8-feature idea: categorical types are one-hot rather
than arbitrary numeric magnitudes.

Optional `--include-responses` adds six header-response features. They require
an explicit verified/unambiguous association. They are **off by default** because
the present matching discrepancies and missingness can bias a classifier. A live
model using this option must wait for completed observations, not predict at
query arrival while using future responses.

`configs/m1_benign_split.json` pins raw identities: `benign_1.pcap` is training;
`benign_2.pcap` is preliminary validation. No independent test is available.
Sequences are grouped by session/client (optionally client/parent), sorted by
integer-precision decimal timestamps and separated at idle gaps over 300 seconds.
Windows are nonoverlapping, with stride 20. Full-length windows are the default;
short tails are discarded, preventing padding amount from becoming a class cue.
Explicit shorter minima are supported with right padding, packed encoders and
masked loss; supervised variable lengths must have equal class-conditional length distributions.
Repeated query packets are retained because they may be real retransmissions;
their identities never appear in features. Windows never share query rows or
cross capture/session splits.

Prepared data in `models/gru/prepared_benign/`:

- Train: 2,529 windows, 50,580 queries (14 tail queries excluded).
- Validation: 1,670 windows, 33,400 queries (6 tail queries excluded).
- Test: 0 windows; do not report test accuracy.
- `train.npz`, `validation.npz`, `test.npz`: raw numerical tensors, lengths, targets.
- Corresponding `_metadata.jsonl` files: source/query identities, kept outside tensors.
- `feature_schema.json`, `normalization.json`, `split_manifest.json`, `dataset_manifest.json`.

Normalization is fit using only valid training tokens, excluding padding;
constant features have scale 1. Validation is never used to fit preprocessing.
Benign captures are adjacent recordings from one host/testbed, so this held-out
capture validation is preliminary and does not establish deployment generalization.

To rebuild, choose a **new** output folder (existing prepared data is protected):

```powershell
.\.venv\Scripts\python.exe -B build_gru_sequences.py `
  --sequence-length 20 --stride 20 --min-length 20 --max-gap-s 300 `
  --output-dir models/gru/prepared_benign_rebuilt
```

## Reproduce dependency installation, smoke check and training

```powershell
Set-Location 'C:\Users\gunn\Desktop\work\DNS\DNSentinel'

# NumPy, dnslib and tldextract are already installed in this project.
.\.venv\Scripts\python.exe -m pip install -r requirements-gru.txt `
  --index-url https://download.pytorch.org/whl/cpu

# Forward pass only, with no optimizer steps or checkpoint writes.
.\.venv\Scripts\python.exe -B -m ml.train_gru `
  --data models/gru/prepared_benign --device cpu --smoke-only

# Reproduce training in a new folder; preserve the completed first run.
.\.venv\Scripts\python.exe -B -u -m ml.train_gru `
  --data models/gru/prepared_benign `
  --output models/gru/m1_benign_ae_run2 `
  --epochs 10 --hidden-size 32 --batch-size 64 `
  --learning-rate 0.001 --dropout 0.1 --patience 3 `
  --seed 42 --device cpu
```

For CUDA, install the appropriate official PyTorch build, then use `--device cuda`
or `--device auto`. CPU is the default. Deterministic algorithms, seeds, CPU
thread count and package versions are recorded. Reproducibility across different
PyTorch/platform versions is not guaranteed. No scikit-learn dependency is needed.

The encoder is one GRU layer with 32 hidden units and latent dropout; the
autoencoder decoder gets zero inputs conditioned on the latent state (no
teacher-forcing shortcut). AdamW, gradient clipping and validation-loss early
stopping are configured. Loss ignores padding. The best checkpoint is selected
using the separate validation capture. A provisional anomaly threshold uses
the 99th percentile of **training** reconstruction errors only.

The completed first run saved these artifacts (a repeated run writes them to its new output folder):

- `models/gru/m1_benign_ae/best.pt`
- `model_config.json`, copied feature/normalization/dataset/split metadata.
- `training_history.csv`: actual epoch training and validation losses.
- `evaluation_metrics.json`: error summaries and held-out benign threshold
  exceedance rate. These are not malicious-traffic precision/recall/F1.

An existing nonempty run folder is protected; use a new `--output` for another run.
An interrupted checkpoint whose threshold is still `None` is incomplete and
cannot be used by the inference interface. No resume command is implemented.

Re-evaluate the completed first run:

```powershell
.\.venv\Scripts\python.exe -B -m ml.evaluate_gru `
  --checkpoint models/gru/m1_benign_ae/best.pt `
  --data models/gru/prepared_benign --split validation
```

## Supervised classifier readiness

`GRUModel(mode="supervised")` uses the packed GRU followed by a small dense
binary head. Training uses a training-only positive-class weight and reports
validation precision/recall/F1, class counts and TN/FP/FN/TP. Threshold is fixed
at 0.5; sigmoid outputs are not calibrated probabilities.

Before using supervised mode, supply a reviewed manifest based on
`configs/m1_supervised_manifest.example.json`. The example deliberately fails
verification and cannot produce training data. Each segment must pin the raw
capture SHA-256, unique session ID, verified evidence, binary label, split and
optional half-open UTC epoch interval. Mixed capture content cannot be labelled
from the filename. All segments from one capture must stay in one split, and
training/validation must both contain verified examples of each class.

```powershell
.\.venv\Scripts\python.exe -B build_gru_sequences.py `
  --mode supervised --split-manifest configs/reviewed_m1_labels.json `
  --output-dir models/gru/prepared_supervised

.\.venv\Scripts\python.exe -B -u -m ml.train_gru `
  --data models/gru/prepared_supervised --output models/gru/m1_supervised `
  --epochs 10 --seed 42 --device cpu
```

## Live shadow inference

`ml.inference.M1Predictor(checkpoint).observe(observation)` buffers ordered
observations separately by client/session and optional parent domain, resets
after idle gaps, and returns `None` until a complete window exists. Input keys:
`client_ip`, `qname`, `qtype_numeric`, `timestamp_monotonic_s` (query-arrival time;
epoch seconds are also accepted), and preferably a restart-specific `session_id`.
The shared feature function ensures offline/live parity. Return fields include
model output/anomaly score, threshold, version, sequence length and prediction
timestamp. `predict(list_of_observations)` supports explicit windows.

`ml.shadow.M1Shadow` now connects this interface to the gateway through a bounded
background queue. It saves normal/anomalous predictions in `m1_predictions` and
worker progress in `m1_runtime` within the existing SQLite database. The existing
dashboard includes an M1 monitor. The saved model uses 20 queries per client,
across domains, and query-only features. Live windows do not overlap and M1 never
blocks. See [launch commands, demonstrations and integration checks](docs/m1-live-demo.md).
Attack-labelled evaluation and detector comparison still require complete
observations and reliable labels; this integration does not establish accuracy.

## Checks performed during preparation

- All 14 PCAPs audited with TShark 4.6.9 and raw SHA-256 verification.
- CSV timestamp consistency, missing responses and query identities checked.
- Both independent-capture sequence sets generated and their manifests saved.
- Preprocessing tests cover feature provenance exclusion, missing/ambiguous
  responses, private numeric types, parent depth, timing, padding normalization,
  unverified-label rejection and confusion-matrix calculation.
- CLI help and Python syntax checked.
- **Completed by the user after preparation:** dependency installation, successful model forward check, 10 training epochs, best-checkpoint persistence, training-only threshold calibration and held-out benign reconstruction evaluation.
- **Still not performed:** supervised classifier training, labelled attack evaluation, independent final testing, and live gateway/dashboard integration.

## New file inventory

- `build_gru_sequences.py`, `requirements-gru.txt`, `README_M1.md`.
- `ml/__init__.py`, `ml/common.py`, `ml/features.py`, `ml/audit_dns_dataset.py`,
  `ml/gru_dataset.py`, `ml/gru_model.py`, `ml/train_gru.py`, `ml/evaluate_gru.py`,
  `ml/inference.py`.
- `configs/m1_benign_split.json`, `configs/m1_supervised_manifest.example.json`.
- `tests/test_m1_preprocessing.py`.
- `models/gru/dataset_audit.json`, `models/gru/planned_experiment.json`,
  `models/gru/preparation_status.json`.
- `models/gru/prepared_benign/`: `train.npz`, `validation.npz`, `test.npz`,
  `train_metadata.jsonl`, `validation_metadata.jsonl`, `test_metadata.jsonl`,
  `feature_schema.json`, `normalization.json`, `split_manifest.json`,
  `dataset_manifest.json`.

M1 did not modify the working detector source files or original extracted dataset. README documentation was updated after training.
