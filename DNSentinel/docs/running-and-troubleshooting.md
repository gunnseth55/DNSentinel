# Running, demonstrations and troubleshooting

[Documentation index](README.md) · [Detector logic](detectors.md) · [Training reference](../README_M1.md)

## Choose the right terminal syntax

The project directory is `C:\Users\gunn\Desktop\work\DNS\DNSentinel`.
The Git repository root is its parent, `C:\Users\gunn\Desktop\work\DNS`.

In **CMD**:

```cmd
cd /d C:\Users\gunn\Desktop\work\DNS\DNSentinel
```

In **PowerShell**:

```powershell
Set-Location 'C:\Users\gunn\Desktop\work\DNS\DNSentinel'
```

The one-line Python commands below work in either shell. PowerShell uses
backticks for continuation and `$_` in pipeline loops. CMD uses different
syntax: do not paste PowerShell loop bodies or closing braces into CMD.

## Prerequisites and local artifacts

Use the existing `.venv`. A fresh machine needs a compatible Python environment
and the project packages: `dnslib`, `tldextract`, `numpy`, `pandas`, and
`streamlit`; M1 additionally needs PyTorch. TShark is needed for the independent
PCAP comparison audit. The recorded training environment used Python 3.13,
PyTorch 2.15.0+cpu and NumPy 2.5.4; version/platform changes can change results.

Raw captures, generated CSV/tensors, runtime SQLite files and model weights
are intentionally ignored by Git. A fresh clone therefore needs local datasets
and a trained checkpoint restored or reproduced before ML commands can run.
Small experiment reports/configurations remain versioned. Do not expect
`best.pt` or raw PCAPs to arrive with the source checkout.

For CPU PyTorch installation in the existing environment:

```text
.\.venv\Scripts\python.exe -m pip install -r requirements-gru.txt --index-url https://download.pytorch.org/whl/cpu
```

See the [M1 reference](../README_M1.md) for extraction, sequence rebuilding and
reviewed label-manifest requirements.

## Start the gateway and dashboard

Keep the server in one terminal:

```text
.\.venv\Scripts\python.exe -u dns_server.py
```

Open a second terminal in the same project directory for queries. Start the
dashboard in a third terminal:

```text
.\.venv\Scripts\python.exe -m streamlit run dashboard.py
```

Open the local URL printed by Streamlit. Its tabs show DNS activity, general
security alerts, P1 monitoring and traffic analysis. The page refreshes roughly
every three seconds. General activity shows up to 500 recent requests; general
alerts and P1 history show up to 300 recent rows. Total counters can therefore
exceed the number of displayed rows.

M1 is available in the **M1 monitor** tab. Follow the [live demo guide](m1-live-demo.md)
for its 20-query warm-up, demonstrations, failure behaviour and saved results.

## Basic gateway checks

```text
.\.venv\Scripts\python.exe dns_client.py demo.test
.\.venv\Scripts\python.exe dns_client.py demo.test AAAA
.\.venv\Scripts\python.exe dns_client.py blocked.test
.\.venv\Scripts\python.exe dns_client.py missing.test
```

Expected results:

| Query | Expected DNS behaviour |
|---|---|
| `demo.test A` | NOERROR and `192.0.2.10`. |
| `demo.test AAAA` | NOERROR without an IPv6 answer. |
| `blocked.test` | REFUSED by static blocklist. |
| `missing.test` | NXDOMAIN from the local test handler. |

These commands test the local gateway directly, without changing Windows DNS.

## Show B1 and P1 explanations

A long label and a deeply nested name:

```text
.\.venv\Scripts\python.exe dns_client.py aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.length-example.test
.\.venv\Scripts\python.exe dns_client.py a.b.c.d.e.depth-example.test
```

Look for B1 R1 and R7 respectively. Other rules can also trigger if the same
group already has recent traffic. In the dashboard, choose **Security alerts →
Detection engine → B1** to see IDs, reasons and measured values.

For a staged P1 demonstration, use a parent with no other recent test queries:

```text
.\.venv\Scripts\python.exe dns_client.py q1.walkthrough.test
.\.venv\Scripts\python.exe dns_client.py q2.walkthrough.test
.\.venv\Scripts\python.exe dns_client.py q3.walkthrough.test
```

Wait about 5 seconds for evaluation: P1 can show WATCH. While the queries are
still within the 60-second window, send:

```text
.\.venv\Scripts\python.exe dns_client.py q4.walkthrough.test
```

After the next evaluation, naming plus response evidence can show ALERT. B1
can independently report R3 and R5. The client still prints NXDOMAIN because
security observation does not change these local test answers. Review
**P1 monitor** for the pair's state, evidence, measurements, transitions and
contributing samples. Wait for expiry to observe the state clear.

For R8, send ten private-use type queries to the same parent.
Use the loop for your shell, keeping the requests within 60 seconds.

**CMD, entered interactively** (single `%N`; batch files use `%%N`):

```cmd
for /l %N in (1,1,10) do .\.venv\Scripts\python.exe dns_client.py same.types-example.test TYPE65280
```

**PowerShell**:

```powershell
1..10 | ForEach-Object { .\.venv\Scripts\python.exe dns_client.py same.types-example.test TYPE65280 }
```

R4/R5 may accompany R8 because those repeated local queries also form a burst
and return NXDOMAIN. A B1 incident row can accumulate these IDs.

## Evaluate or repeat M1 training

With the local completed checkpoint and prepared data present:

```text
.\.venv\Scripts\python.exe -m ml.evaluate_gru --checkpoint models/gru/m1_benign_ae/best.pt --data models/gru/prepared_benign --split validation --device cpu
```

This recomputes reconstruction statistics and benign threshold exceedances.
It writes `validation_metrics.json` beside the checkpoint. It does not train
or calculate attack-detection accuracy. The prepared test split is empty.

Before a new training run, check the forward pass:

```text
.\.venv\Scripts\python.exe -m ml.train_gru --data models/gru/prepared_benign --device cpu --smoke-only
```

To repeat training, choose a fresh output directory:

```text
.\.venv\Scripts\python.exe -u -m ml.train_gru --data models/gru/prepared_benign --output models/gru/m1_benign_ae_run2 --epochs 10 --hidden-size 32 --batch-size 64 --learning-rate 0.001 --dropout 0.1 --patience 3 --seed 42 --device cpu
```

Existing nonempty output directories are protected. Pick another name if
`m1_benign_ae_run2` already exists; preserve the original run.

## Common problems

| Symptom | Explanation and next check |
|---|---|
| Python path not recognized | Check your working directory: `.venv` is inside `DNSentinel`, not the Git root. |
| WinError 10048 | Another process owns port 5300. Find the original server terminal and stop it before restarting. |
| Ctrl+C appears ineffective | Focus the running terminal, clear selected text with Esc, then press Ctrl+C. Confirm it is the terminal that launched the server. |
| `Server: UnKnown` from nslookup | Reverse name lookup for the server failed; that label alone does not prove the DNS gateway failed. |
| nslookup reports no response | This occurred during development without a confirmed cause. Check with the project client, correct port, server log and process state. |
| Client prints NXDOMAIN during a security demo | Expected for unconfigured `.test` names. Look for the alert in the server terminal/SQLite/dashboard. |
| P1 does not show WATCH before ALERT | Several evidence families can be present at its first scheduled evaluation. Direct NORMAL → ALERT is allowed. |
| P1 never alerts on repeated `demo.test` | Parent-only queries are excluded; its naming condition also needs qualifying labels or distinct subdomains. |
| New code seems inactive | Restart the server process to load edited Python files. Rolling histories reset; stored history remains. |
| Dashboard counts differ from table length | Counters use all stored rows; tables display limited recent windows. |
| GRU output directory is not empty | The protection prevents accidentally replacing a completed experiment; use a new output path. |
| Missing `.pt`, `.npz` or raw data after cloning | These local artifacts are ignored by Git; restore/reproduce them first. |
| Attack capture yields few/no observations | Inspect the audit's question failures and snaplen; long DNS names may be irrecoverably truncated. |
| `$_` or `}` errors in CMD | Those are PowerShell constructs. Use CMD syntax or switch to PowerShell before executing its scripts. |

For port ownership, this read-only command works in CMD or PowerShell:

```text
netstat -ano -p udp | findstr :5300
```

Identify the owning process before stopping anything. Keep source files,
datasets and model artifacts intact while diagnosing a process/port issue.

## Git and project files

From the Git root, `git status` shows pending source/documentation changes.
The ignore file excludes local data, caches, databases and model weights while
retaining small configuration/metric records. Adding an ignore rule does not
remove a file already committed in history. Attack PCAP payloads previously
triggered GitHub secret scanning; keep such captures local rather than bypassing
push protection or uploading raw payloads with the code.
