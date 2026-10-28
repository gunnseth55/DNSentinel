# DNSentinel explained

DNSentinel is a local DNS gateway with several ways of spotting suspicious
activity. It also includes a separately trained GRU autoencoder experiment.
These guides explain what the system does, how its parts connect, and what its
current results support.

| Guide | What you will learn |
|---|---|
| [Architecture and request flow](architecture.md) | What happens to a DNS request, where decisions are made, and what is stored. |
| [Detectors explained](detectors.md) | B0, the original behaviour detector, B1's eight rules, and P1's state machine. |
| [Dataset and M1 training](dataset-and-m1.md) | Why the first model learns benign patterns, its features, and actual results. |
| [M1 live demo](m1-live-demo.md) | Launch the gateway/dashboard, demonstrate shadow inference and inspect actual integration results. |
| [Extraction v2 audit and results](extraction-v2.md) | Complete DNS/mDNS extraction, TCP support, response confidence, and the actual 14-capture comparison. |
| [Running, demos and troubleshooting](running-and-troubleshooting.md) | Commands for Windows, useful demonstrations, and common problems. |
| [Glossary](glossary.md) | Plain-language definitions of DNS, ML and evaluation terminology. |

For a first reading, start with the architecture and detector guides. For a
project presentation, use their diagrams, then explain the M1 results and their
limits. For exact training commands and the complete epoch table, see the
[M1 reference guide](../README_M1.md) and [project README](../README.md).

## Current implementation boundary

- The UDP gateway, SQLite logging, B0, B1, original behaviour detector, P1, and
  Streamlit dashboard are implemented.
- The first **benign-reference M1 autoencoder** has completed 10 training epochs.
- M1 now receives live observations in a bounded background worker, stores
  reconstruction errors in SQLite and appears in the dashboard's M1 monitor.
- Static blocked-domain matching refuses queries. Behavioural/model alerts do
  not currently introduce automatic blocking.
- Attack-detection accuracy and a controlled B0/B1/P1/M1 comparison have not been
  established.

The training figures in these guides describe the saved run
`M1-benign_autoencoder-20261028T142050413090Z`. They are a record of that
experiment, not continuously updated benchmark results.
