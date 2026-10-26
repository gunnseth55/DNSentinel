"""P1 corroborated DNS detector. Does not perform blocking.

A 60-second rolling window is evaluated on a 5-second schedule.
A name-pattern observation creates WATCH. Naming plus either independent
burst timing or NXDOMAIN response evidence creates ALERT.

The detector keeps state in memory; callers persist returned transitions.
"""

from collections import defaultdict, deque
from math import log2
from time import monotonic
from collections import Counter

import tldextract


EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, extra_suffixes=("test",)
)


def entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((n / len(value)) * log2(n / len(value)) for n in counts.values())


class P1Detector:
    def __init__(self, window_seconds=60, interval_seconds=5):
        self.window_seconds = window_seconds
        self.interval_seconds = interval_seconds
        self.histories = defaultdict(deque)
        self.states = {}
        self.last_evaluation = None

    def observe(self, client_ip, domain, response_code, status, now=None):
        """Save an eligible completed DNS transaction for later evaluation."""
        if status not in ("FORWARDED", "LOCAL", "LOCAL_TEST"):
            return False
        if response_code not in ("NOERROR", "NXDOMAIN"):
            return False

        domain = domain.lower().rstrip(".")
        parts = EXTRACT(domain)
        if not (parts.domain and parts.suffix and parts.subdomain):
            return False

        parent = f"{parts.domain}.{parts.suffix}"
        label = parts.subdomain.split(".")[0]
        key = (client_ip, parent)
        timestamp = monotonic() if now is None else now
        self.histories[key].append(
            {
                "time": timestamp,
                "domain": domain,
                "label": label,
                "rcode": response_code,
                "source": status,
            }
        )
        return True

    def evaluate(self, now=None):
        """Return only state transitions; safe to call more often than every 5s."""
        timestamp = monotonic() if now is None else now
        if (self.last_evaluation is not None
                and timestamp - self.last_evaluation < self.interval_seconds):
            return []
        self.last_evaluation = timestamp
        transitions = []

        keys = set(self.histories) | set(self.states)
        for key in sorted(keys):
            history = self.histories.get(key, deque())
            while history and timestamp - history[0]["time"] > self.window_seconds:
                history.popleft()

            items = list(history)
            count = len(items)
            unique_count = len({item["domain"] for item in items})
            unique_ratio = unique_count / count if count else 0.0
            maximum_length = max((len(item["label"]) for item in items), default=0)
            maximum_entropy = max((entropy(item["label"]) for item in items), default=0.0)
            has_high_entropy_label = any(
                len(item["label"]) >= 16 and entropy(item["label"]) >= 3.5
                for item in items
            )
            burst_count = sum(timestamp - item["time"] <= 15 for item in items)
            nx_count = sum(item["rcode"] == "NXDOMAIN" for item in items)
            nx_ratio = nx_count / count if count else 0.0

            # Multiple naming indicators are ONE evidence family.
            naming = (
                (unique_count >= 3 and unique_ratio >= 0.8)
             or maximum_length >= 30
                or has_high_entropy_label
            )
            timing = burst_count >= 5
            response = nx_count >= 4 and nx_ratio >= 0.8

            target_state = (
                "ALERT" if naming and (timing or response)
                else "WATCH" if naming else "NORMAL"
            )
            previous = self.states.get(key, "NORMAL")

            if target_state != previous:
                self.states[key] = target_state
                transitions.append({
                    "clock_seconds": round(timestamp, 3),
                    "client_ip": key[0],
                    "parent_domain": key[1],
                    "from_state": previous,
                    "to_state": target_state,
                    "evidence": {
                        "naming": naming,
                        "timing": timing,
                        "response": response,
                    },
                    "features": {
                        "query_count": count,
                        "unique_subdomains": unique_count,
                        "unique_ratio": round(unique_ratio, 3),
                        "max_label_length": maximum_length,
                        "max_label_entropy": round(maximum_entropy, 3),
                        "queries_last_15s": burst_count,
                        "nxdomain_count": nx_count,
                        "nxdomain_ratio": round(nx_ratio, 3),
                    },
                    "samples": [
                        {"domain": item["domain"], "response": item["rcode"],
                         "source": item["source"]}
                        for item in items[-5:]
                    ],
                })

            # Expired groups do not occupy memory indefinitely.
            if not history:
                self.histories.pop(key, None)
                self.states.pop(key, None)

        return transitions
