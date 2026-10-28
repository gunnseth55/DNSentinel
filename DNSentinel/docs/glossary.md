# Glossary

[Documentation index](README.md)

| Term | Meaning in DNSentinel |
|---|---|
| DNS | Domain Name System: resolves names into records such as IP addresses. |
| Query / observation | A DNS question; an extracted/completed observation may also include its response outcome. |
| QNAME | The full queried name, such as `a.example.com`. Normalization lowercases it and removes a trailing dot. |
| Label | One dot-separated part of a name. The leftmost label in `a.example.com` is `a`. |
| Registered / parent domain | The registrable domain determined using public suffix rules. For `a.example.co.uk`, it is `example.co.uk`. |
| Subdomain | A name below that parent. `a.b.example.co.uk` has two subdomain labels: `a` and `b`. |
| A / AAAA | DNS record types for IPv4 / IPv6 addresses. |
| TXT / NULL / private-use type | DNS types counted by B1 R8. Private-use means numeric types 65280-65534. |
| NOERROR | DNS response code indicating no DNS-level error; not a security verdict. |
| NXDOMAIN | The queried domain name does not exist. Multiple failures can form behavioural evidence. |
| REFUSED | The DNS server refused the operation, such as a static blocklist match. |
| SERVFAIL | DNS processing failed, such as an upstream timeout. It must not be counted as NXDOMAIN. |
| Shannon entropy | A numerical measure of character distribution/randomness; varied encoded labels can have high entropy, but entropy alone does not prove an attack. |
| Rolling window | Recent observations kept for a time interval, rather than all historical traffic. |
| Monotonic time | A clock used for elapsed durations that is not adjusted like wall-clock date/time. |
| Incident | A continuing client/domain pattern whose B1 trigger updates are merged into one stored alert row. |
| Evidence family | P1's grouping of indicators into naming, timing or response evidence. Multiple naming indicators do not create multiple independent families. |
| PCAP | A file of captured network packets. It can contain truncated rather than complete packet bytes. |
| Snapshot length / snaplen | Maximum bytes retained per captured packet. These captures use 96 bytes, often too short for encoded attack names. |
| Capture provenance | Where a row came from: file, recording and source category. It is not automatically a verified target label. |
| Label / target in ML | The desired class during supervised learning. This meaning differs from a DNS label. |
| Feature | A numerical measurement given to a model, such as label length or query gap. Capture identity is intentionally not an M1 feature. |
| One-hot encoding | Represents a category with separate indicator positions rather than an arbitrary ordered number. |
| Sequence | Ordered queries treated as one model example. The first M1 run uses 20 queries with 12 features each. |
| Batch | A group of examples processed together. Batch size 64 means up to 64 sequences, not 64 individual DNS queries. |
| Epoch | One training pass through the training sequence set. The first M1 run completed 10 epochs. |
| GRU | Gated Recurrent Unit: a recurrent neural network component that carries learned information along a sequence. |
| Autoencoder | A model trained to reconstruct its input representation. M1's first run learns benign-reference DNS feature sequences. |
| Reconstruction error | Difference between input and reconstructed features. M1 uses it as an anomaly score. |
| Normalization | Applying training-derived means/scales to feature values. Validation/inference reuse the same parameters. |
| Padding / mask | Extra entries for shorter sequences, plus a way to exclude them from model/loss calculations. Default M1 windows are full length. |
| Training / validation / test | Data for learning weights / selecting model settings and checkpoint / independent final assessment. Current M1 has training and preliminary validation, with no independent test capture. |
| Leakage | Information from evaluation data or target-related artifacts improperly helping training. Randomly splitting overlapping query windows is a common example. |
| Dropout | Training-time random removal of some neural activations to discourage dependence on particular activations. Disabled during evaluation. |
| Early stopping | Ending training after validation stops improving. The first run completed all 10 epochs without triggering it. |
| Checkpoint | Saved neural weights plus relevant configuration/preprocessing metadata. |
| Anomaly threshold | A cutoff on reconstruction error. M1's provisional cutoff is derived from training errors, not a maliciousness probability. |
| Precision / recall / F1 | Classifier metrics requiring meaningful class labels. They are not established by benign reconstruction loss. |
| False-alarm candidate | A benign-reference validation sequence flagged as unusual. It merits inspection; the flag is not an attack finding. |
| Shadow mode | Compute/log model outputs alongside the gateway without changing DNS replies or automatically blocking traffic. M1's live connection is still planned. |
