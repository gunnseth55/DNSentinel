# M1 live shadow demo

M1 loads the existing benign-only GRU autoencoder at
`models/gru/m1_benign_ae/best.pt`. No training is performed. The checkpoint embeds
the feature schema, training normalization and threshold **1.161235432624816**.
Its version is `M1-benign_autoencoder-20261028T142050413090Z`.

## Start the gateway and dashboard

In PowerShell terminal 1:

```powershell
Set-Location C:\Users\gunn\Desktop\work\DNS\DNSentinel
.\.venv\Scripts\python.exe -B -u dns_server.py
```

Wait for `M1 shadow ready`. In terminal 2:

```powershell
Set-Location C:\Users\gunn\Desktop\work\DNS\DNSentinel
.\.venv\Scripts\python.exe -B -m streamlit run dashboard.py
```

Open `http://localhost:8501` and select **M1 monitor**. This uses the existing
dashboard; B0/B1 alerts and P1 remain on their existing tabs. All traffic below
uses the local gateway at `127.0.0.1:5300` and reserved `.test` domains.

## Demonstrate two windows

In terminal 3, start with a freshly restarted gateway so the client's M1 buffer
is empty. Other DNS tools using the same client IP contribute to that buffer too.

```powershell
Set-Location C:\Users\gunn\Desktop\work\DNS\DNSentinel

# Simple local reference traffic: one complete 20-query window.
1..20 | ForEach-Object {
    .\.venv\Scripts\python.exe -B dns_client.py demo.test
    Start-Sleep -Milliseconds 200
}

# Suspicious-looking names: another complete window; expect local NXDOMAIN replies.
1..20 | ForEach-Object {
    $name = ('{0:D2}' -f $_) + 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.payload.demo.test'
    .\.venv\Scripts\python.exe -B dns_client.py $name
    Start-Sleep -Milliseconds 200
}
```

Inspect reconstruction error, the saved threshold, NORMAL/ANOMALY, contributing
domains, model version and distribution warnings. The simple local traffic is
also outside the Alexa-domain training reference; these commands demonstrate
inference and persistence, not measured attack detection accuracy. Scores vary
with query timing. B0/B1/P1 can independently react to this traffic.

## Sequence and failure behaviour

The saved schema groups **by client across domains**, not separately by domain.
M1 uses exactly those semantics; each result lists its parent domains and QNAMEs.
Every 20 queries form one non-overlapping window. Partial windows are not padded
into artificial observations or scored: the checkpoint requires all 20. An idle
gap over 300 seconds resets a buffer when the next observation arrives. Gateway
restarts, queue drops and processing errors also prevent incomplete windows from
being stitched together. At most 2,048 client/session buffers are retained;
the least recently active buffer is evicted when that limit is reached.

The 12 features are leftmost-label length, full QNAME length, leftmost-label
entropy, digit ratio, subdomain depth, log1p within-window query gap, and six
query-type indicators (A, AAAA, TXT, NULL, private-use, other). The first gap is
zero, as during training. This checkpoint has no response input features, so
missing responses and SERVFAIL do not become invented model input values.

The gateway submits completed observations with monotonic arrival timestamps
after sending the DNS reply. A bounded 256-item background queue performs CPU
inference and SQLite writes. It never changes DNS answers or P1 state. Missing
PyTorch, a missing/invalid checkpoint, inference failures or SQLite errors leave
DNS request handling independent. Runtime status exposes errors, warm-up counts
and dropped observations. There is no automatic blocking.

To disable M1 before starting the gateway:

```powershell
$env:DNSENTINEL_M1 = '0'
.\.venv\Scripts\python.exe -B -u dns_server.py
# Re-enable for a subsequent gateway launch:
Remove-Item Env:DNSENTINEL_M1
```

Optional `DNSENTINEL_M1_CHECKPOINT` selects a checkpoint; incompatible schemas
disable M1 rather than silently changing features. `DNSENTINEL_DB_PATH` selects
an alternative SQLite database; set the same value in gateway and dashboard
terminals if using it. Defaults use the existing `dns_events.db`.

## SQLite and interpretation

`m1_predictions` stores every completed inference, including normal results:
timestamp, client IP, QNAMEs and parents as JSON, reconstruction error, threshold,
anomaly flag, model version, actual/configured sequence sizes, distribution
warnings and gateway session ID. `m1_runtime` holds the latest worker status and
progress. Existing detector tables and alert logic are unchanged. These are new
tables in the existing database, not a new production database.

The model learned benign Alexa-domain traffic, with only A queries in its
training reference. Non-A types, `.test` names and numeric features exceeding
five training standard deviations produce diagnostic warnings. These checks
are indicators of distribution differences, not a comprehensive drift test.
An anomaly is not proof of exfiltration; NORMAL does not prove safety. The
threshold is a training-error percentile, not a calibrated attack probability.
The model has not been evaluated against trustworthy attack-labelled sessions.

## Integration checks actually run

The isolated gateway checks used the real checkpoint, UDP port 5300 and a separate
check database, preserving production history. They verified no prediction after
19 queries, one prediction at 20, no overlap, and dashboard SQLite loading.
Observed live reconstruction errors were **0.1892545074** for 20 `demo.test`
queries (NORMAL) and **28.4942512512** for 20 long names (ANOMALY), against
threshold **1.1612354326**. These values reflect that check's timing.

The same checks preserved NOERROR, NXDOMAIN, blocked REFUSED, private-use type
65280 handling, existing detector alerts and P1 transitions. Separate gateway
launches verified both explicitly disabled M1 and a missing checkpoint still
served DNS. Check results are in
`models/gru/m1_demo_check_20261028T203645Z/check_results.json`; no model was trained.
