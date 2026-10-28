# DNSentinel — Implementation & GRU Progress

**Project:** Windows-based DNS security gateway and explainable threat detection mini-project  
**Project directory:** `C:\Users\gunn\Desktop\work\DNS\DNSentinel`  
**Progress snapshot:** 28 October 2026  
**Current milestone:** The trained benign-only M1 GRU autoencoder now runs in live shadow mode, records SQLite predictions and appears on the dashboard. Attack evaluation remains pending. See [live demo commands and verified results](docs/m1-live-demo.md).

**Explanatory guides:** Start with the [documentation index](docs/README.md) for
architecture diagrams, detector logic, the dataset/model explanation, Windows
demonstrations, troubleshooting and a glossary.

## 1. Objective

DNSentinel is a local DNS security gateway that logs DNS activity and compares simple rules, expanded independent rules, and a corroborated state-machine detector. **M1, a GRU-based recurrent neural network**, is trained as a benign-reference sequence autoencoder for DNS anomaly research. Its live integration uses **shadow mode** (monitor and log predictions; do not automatically block DNS).

## 2. Implemented components

| Component | Current progress |
|---|---|
| `dns_server.py` | Python UDP DNS gateway on `127.0.0.1:5300`, forwards applicable requests to `1.1.1.1:53`, handles local `.test` cases and static blocked domains; records DNS activity in SQLite. |
| `dns_client.py` | Manual command-line DNS query generator, including `A` and private-use type queries. |
| `security.py` — B0 | Basic per-query heuristic using long-label length and entropy. |
| `behaviour.py` | Earlier rolling-window behavioural detector; demonstrated unique subdomain + NXDOMAIN alerts. |
| `p1_detector.py` — P1 | Corroborated detector with naming/timing/response evidence and `NORMAL → WATCH → ALERT → NORMAL` state transitions. User confirmed P1 working. |
| `b1_detector.py` — B1 | Independent-rule baseline; manual runs triggered length, diversity, burst, NXDOMAIN, depth, and unusual-record-type rules. |
| `dashboard.py` | Existing DNS activity, detector alerts, P1 monitor, M1 shadow predictions and traffic analysis tabs. |
| `dns_events.db` | SQLite DNS request logs, alerts, and P1 transitions according to the implemented project. |

**Demonstrated B1 checks:**
- 30-character label: R1 alert; P1 moved from NORMAL to WATCH.
- Five unique `diversitycheck.test` subdomains: B1 R3/R4/R5 and P1 NORMAL to ALERT.
- Five nested labels under `depthcheck.test`: B1 R7.
- Ten `TYPE65280` queries: R8 unusual-record-type detection. B1 now uses consecutive IDs R1-R8.

**Current design caveat:** B1 can emit repeated alerts during one evolving incident; incident aggregation/cooldown still needs verification. Distinguish these alerts from unique incidents during later evaluation.

## 3. M1: GRU experiment — dataset status

**Dataset:** CIC-Bell-DNS-EXF-2021 (benign + light/heavy exfiltration captures). The user downloaded and extracted **14 PCAPs**, located under:

```text
data/cic_bell_exf_2021/
├── raw/
│   ├── benign/Benign/                 # benign_1.pcap, benign_2.pcap
│   ├── attack_light/Attacks/          # light_{audio,compressed,exe,image,text,video}.pcap
│   └── attack_heavy/Attacks/          # heavy_{audio,compressed,exe,image,text,video}.pcap
└── processed/
    ├── dns_observations.csv           # earlier 2-capture extraction
    ├── extraction_audit.json
    └── all_captures/
        ├── dns_observations.csv       # all 14 captures (~31.5 MB)
        └── extraction_audit.json      # audit (~50 KB)
```

`prepare_gru_dataset.py` has run successfully (exit code 0) on all 14 captures. The script's help describes support for **classic Ethernet PCAP, IPv4/IPv6, UDP port 53**; **DNS-over-TCP/reassembly and training labels are not part of this extraction step**. Capture group is provenance, **not ground-truth malicious/benign classification**.

### Observations extracted

| Capture | DNS observations | Script-reported matched responses |
|---|---:|---:|
| `benign_1.pcap` | 50,594 | 50,124 |
| `benign_2.pcap` | 33,406 | 33,386 |
| `light_audio.pcap` | 28 | 28 |
| `light_compressed.pcap` | 19 | 19 |
| `light_exe.pcap` | 13 | 13 |
| `light_image.pcap` | 0 | 0 |
| `light_text.pcap` | 8 | 8 |
| `light_video.pcap` | 8 | 8 |
| `heavy_audio.pcap` | 98 | 98 |
| `heavy_compressed.pcap` | 100 | 100 |
| `heavy_exe.pcap` | 112 | 112 |
| `heavy_image.pcap` | 90 | 90 |
| `heavy_text.pcap` | 223 | 219 |
| `heavy_video.pcap` | 136 | 66 |
| **Total** | **84,835** | **84,271** |

**Breakdown:** 84,000 benign-capture observations, 76 light-attack-capture observations, and 759 heavy-attack-capture observations. These are *capture-origin counts*, not validated class totals.

### Extraction and label limitations

The independent M1 audit has now identified truncation as the main cause of missing attack questions and reproduced the TShark response-linking discrepancy. These data-quality limits remain important; see the audit findings and actual training results in section 5. Capture categories are not per-query attack labels. The first experiment therefore trains only on publisher-designated benign recordings and leaves attack classification metrics unavailable.

## 4. Useful PowerShell commands

Run from `C:\Users\gunn\Desktop\work\DNS\DNSentinel` in the project virtual environment:

```powershell
# Discover PCAPs regardless of nested extract folder names
$raw = '.\data\cic_bell_exf_2021\raw'
$pcaps = @(Get-ChildItem $raw -Recurse -File |
    Where-Object { $_.Extension -eq '.pcap' } |
    Select-Object -ExpandProperty FullName)
Write-Host 'Found PCAP files:' $pcaps.Count

# Re-extract all captures (uses explicit file paths, not folder args)
python -u .\prepare_gru_dataset.py --input $pcaps `
    --output-dir '.\data\cic_bell_exf_2021\processed\all_captures_reextracted'

# Check extraction files
Get-ChildItem '.\data\cic_bell_exf_2021\processed\all_captures' -File

# Inspect provenance groups
Import-Csv '.\data\cic_bell_exf_2021\processed\all_captures\dns_observations.csv' |
    Group-Object capture_group | Select-Object Name,Count
```

## 5. M1 implementation and completed first training run

**Completed on 28 October 2026:** the user installed PyTorch, passed the forward-only smoke check, and trained the first M1 experiment for all 10 epochs on CPU. Results below were checked against the saved configuration, history and evaluation JSON, rather than inferred from planned settings.

**Training mode:** benign-reference GRU sequence autoencoder. This model learns to reconstruct normal DNS feature sequences. Its reconstruction error is an anomaly score, not a confirmed attack label. A supervised GRU classifier is implemented separately but has not been trained because reliable attack labels and representative complete attack queries are still unavailable.

### Implemented files

| File/component | Purpose |
|---|---|
| [`build_gru_sequences.py`](build_gru_sequences.py) | Validates split manifests, groups chronological observations and creates nonoverlapping sequence tensors. |
| `ml/audit_dns_dataset.py` | Independent CSV/raw-PCAP/TShark audit; preserves original extraction outputs. |
| `ml/features.py` | Shared offline/live feature calculation using existing domain extraction and entropy logic. |
| `ml/gru_dataset.py` | Dataset loading, integrity checks, valid-token normalization and padding masks. |
| `ml/gru_model.py` | One-layer GRU encoder, GRU reconstruction decoder and optional supervised binary head. |
| `ml/train_gru.py` | Seeded AdamW training, gradient clipping, validation early stopping and checkpoint persistence. |
| `ml/evaluate_gru.py` | Saved-checkpoint evaluation; separates reconstruction statistics from supervised classification metrics. |
| `ml/inference.py` | Ordered-observation prediction/buffering interface using saved preprocessing. |
| `ml/shadow.py`, `m1_dashboard.py` | Bounded background M1 inference, SQLite persistence, runtime status and dashboard results. |
| `configs/m1_benign_split.json` | Raw-capture hashes and independent benign training/validation assignments. |
| `configs/m1_supervised_manifest.example.json` | Deliberately unverified template for future reviewed query/session labels. |
| `tests/test_m1_preprocessing.py` | Eight passing checks for feature leakage, timing, masks, label verification and metrics. |
| `requirements-gru.txt` | Minimal additional PyTorch dependency; no scikit-learn dependency. |

Full implementation and file inventory: [README_M1.md](README_M1.md).

### Dataset audit findings

- All 14 raw capture SHA-256 identities verified against the extraction audit. Original CSV/PCAP files were preserved.
- CSV timestamp ordering was checked; epoch/ISO timestamps agreed within the audit tolerance. Source capture/client identities remain metadata, not model inputs.
- The attack captures contain **252,447 UDP/53 queries**, but **251,612** questions are incomplete in the **96-byte** captures. The 835 recovered attack-capture observations are not 835 verified attacks.
- `light_image.pcap` has **489 DNS queries**, all with incomplete questions, explaining its zero extracted rows.
- TShark found no additional complete questions missing from the CSV and no recognized DNS outside UDP/53 in these files. This does not rule out concealed or encrypted traffic.
- The CSV contains **564 missing responses**, **23,550 repeated-outstanding-query rows**, and **46,087 ambiguous response-timing rows**. Repeated queries are retained and uncertainty is flagged.
- Python associates **50,124** queries in `benign_1.pcap`; TShark `dns.response_to` references **15,561** distinct queries. Different association/dissection behaviour, repeated questions and truncated answer sections prevent treating those counts as equivalent ground truth.
- The existing extractor matches in packet-file order before sorting query rows; timestamp regressions can cause missed matches. Original response associations were not silently rewritten.
- Published attack schedules and one recovered query under `cicresearch.ca` are leads for label investigation, not justification for labelling all traffic in an attack capture malicious. Local UTC/session mappings need verification.

Detailed evidence: [`models/gru/dataset_audit.json`](models/gru/dataset_audit.json).

### Features and sequence construction

Input shape is **20 chronological queries x 12 numerical features**:

1. Leftmost label length.
2. Normalized full QNAME length, excluding trailing dot.
3. Leftmost label Shannon entropy.
4. Leftmost label digit ratio.
5. Subdomain-label count below the registered domain.
6. `log1p` of the within-window previous-query time gap; first query is zero.
7-12. One-hot query type: A, AAAA, TXT, NULL, private-use 65280-65534, or other.

Capture/category/filename, source identities, absolute timestamps, domain identities, response latency and capture artefact flags are excluded from model features. Optional response features exist but were **disabled for this experiment** because of matching uncertainty.

Sequences are grouped by capture/session and client, sorted chronologically, separated by idle gaps over 300 seconds, and chunked with length/stride 20. No query row is reused in another window or split. Padding/packed-sequence support exists, but this experiment uses full 20-query windows and discards short tails.

| Split | Recording | Sequences | Queries used | Short-tail queries excluded |
|---|---|---:|---:|---:|
| Training | `benign_1.pcap` | 2,529 | 50,580 | 14 |
| Preliminary validation | `benign_2.pcap` | 1,670 | 33,400 | 6 |
| Independent test | Not available | 0 | 0 | 0 |

Normalization uses only the **50,580 valid training tokens**, with padding excluded and constant-feature scale set to 1. Validation data does not fit normalization. The benign recordings are adjacent captures from the same host/testbed, limiting generalization claims.

Prepared tensors and metadata: [`models/gru/prepared_benign/`](models/gru/prepared_benign/).

### Architecture and actual training settings

- Encoder: **one GRU layer, 32 hidden units**.
- Decoder: GRU conditioned on the encoded state, with zero inputs rather than a teacher-forcing copying shortcut; dense output reconstructs 12 features per timestep.
- Dropout: **0.1**; batch size: **64**.
- Optimizer: **AdamW**, learning rate **0.001**, weight decay **0.0001**.
- Loss: masked per-sequence mean squared reconstruction error; gradient norm clipped to 1.0.
- Maximum epochs: **10**; patience **3**, minimum improvement **0.00001**. All 10 epochs ran; early stopping was not triggered.
- Seed: **42**; device: **CPU**; CPU threads: **2**; deterministic algorithms enabled.
- Recorded environment: PyTorch **2.15.0+cpu**, NumPy **2.5.4**. Reproducibility across package/platform versions is not guaranteed.
- Smoke check passed: **(64, 20, 12) -> (64, 20, 12)**, without training in that smoke step.
- Model version: `M1-benign_autoencoder-20261028T142050413090Z`.

### Actual epoch-by-epoch losses

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

The lowest validation loss was at **epoch 10**, so its weights were saved. Training and validation losses both decreased, with no obvious divergence across this run; that does not establish attack-detection accuracy.

### Reconstruction evaluation and provisional threshold

| Metric | Actual result |
|---|---:|
| Best validation loss | 0.46097860 |
| Training mean reconstruction error, evaluation mode | 0.45342292 |
| Validation mean reconstruction error | 0.46097860 |
| Training 99th-percentile anomaly threshold | 1.16123543 |
| Validation median reconstruction error | 0.42916478 |
| Validation 99th-percentile reconstruction error | 1.03046466 |
| Validation benign sequences exceeding threshold | 8 / 1670 |
| Validation benign threshold-exceedance rate | 0.47904% |

The threshold was fitted to **training reconstruction errors only**, not validation or attack data. An error above the threshold means unusual relative to this benign reference. The 8 flagged validation windows are preliminary false-alarm candidates, not confirmed malicious traffic.

The epoch training loss differs from the training evaluation error because epoch losses include dropout and changing weights, while post-training evaluation uses the selected model with dropout disabled.

**Not measured:** malicious-traffic precision, recall, F1, attack recall, or independent deployment/test accuracy. Validation was used for checkpoint selection and is not an untouched final test. No claim that M1 outperforms B0/B1/P1 is supported yet.

### Saved run artifacts

- [`best.pt`](models/gru/m1_benign_ae/best.pt)
- [`dataset_manifest.json`](models/gru/m1_benign_ae/dataset_manifest.json)
- [`evaluation_metrics.json`](models/gru/m1_benign_ae/evaluation_metrics.json)
- [`feature_schema.json`](models/gru/m1_benign_ae/feature_schema.json)
- [`model_config.json`](models/gru/m1_benign_ae/model_config.json)
- [`normalization.json`](models/gru/m1_benign_ae/normalization.json)
- [`split_manifest.json`](models/gru/m1_benign_ae/split_manifest.json)
- [`training_history.csv`](models/gru/m1_benign_ae/training_history.csv)

**Checkpoint:** `models/gru/m1_benign_ae/best.pt` (45,461 bytes). Training metadata, feature schema, train-only normalization, split manifest and threshold accompany the weights.

`models/gru/preparation_status.json` and `planned_experiment.json` are historical preparation snapshots. The files in `models/gru/m1_benign_ae/` document the completed training run.

### Reproduce the experiment

Use a **new output directory** to preserve the completed run:

```powershell
Set-Location 'C:\Users\gunn\Desktop\work\DNS\DNSentinel'

# Dependency installation, if recreating the environment.
.\.venv\Scripts\python.exe -m pip install -r requirements-gru.txt `
  --index-url https://download.pytorch.org/whl/cpu

# Forward pass only.
.\.venv\Scripts\python.exe -B -m ml.train_gru `
  --data models/gru/prepared_benign --device cpu --smoke-only

# Repeat the same training settings in a fresh run directory.
.\.venv\Scripts\python.exe -B -u -m ml.train_gru `
  --data models/gru/prepared_benign `
  --output models/gru/m1_benign_ae_run2 `
  --epochs 10 --hidden-size 32 --batch-size 64 `
  --learning-rate 0.001 --dropout 0.1 --patience 3 `
  --seed 42 --device cpu

# Re-evaluate the original saved model on the validation capture.
.\.venv\Scripts\python.exe -B -m ml.evaluate_gru `
  --checkpoint models/gru/m1_benign_ae/best.pt `
  --data models/gru/prepared_benign --split validation
```

## 6. Next steps

1. Inspect the eight flagged benign windows and their query metadata before interpreting the provisional anomaly threshold.
2. Obtain captures with complete DNS questions, verify attack/session timing and query labels, and retain unknown labels where evidence is insufficient.
3. Evaluate M1 on representative held-out attack and benign sessions; compare B0/B1/P1/M1 using the same labelled data and explicit false-alarm analysis.
4. Review optional response features only after matching/provenance issues are resolved.
5. Review the implemented [live M1 shadow demo](docs/m1-live-demo.md), including distribution warnings and operational results.
6. Keep automatic blocking and changes to P1's state machine out of the initial M1 integration.

## 7. Current project status

**Completed:** working DNS gateway and B0/B1/P1 demonstrations; 14-capture extraction; independent TShark/source audit; leakage-aware preprocessing; separate-capture train/validation sets; M1 autoencoder and supervised-ready code; successful forward check; first 10-epoch CPU training run; saved best checkpoint and reconstruction metrics.

**Still pending:** reliable attack/query labels, representative complete attack sequences, supervised classifier training, attack-detection metrics and independent final testing. Live M1 shadow integration and dashboard display are implemented and checked.

**Interpretation rule:** reconstruction improvement and a low benign validation exceedance rate do not establish malicious-traffic detection accuracy.
