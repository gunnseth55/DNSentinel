"""Independent-rule DNS baseline; Core R1-R5 or Expanded R1-R8.

Only completed, eligible transactions enter the rolling windows. Each observe()
evaluates all enabled rules. Continuing incidents merge until a clear evaluation
or a gap longer than cooldown_seconds. No blocking or probability score is used.
"""

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from uuid import uuid4

# Reuse P1's offline public-suffix extractor (including .test) and entropy.
from p1_detector import EXTRACT, entropy


CORE_RULES = ("R1", "R2", "R3", "R4", "R5")
EXPANDED_RULES = CORE_RULES + ("R6", "R7", "R8")


@dataclass(frozen=True)
class B1Thresholds:
    window_seconds: float = 60
    long_label_length: int = 30
    entropy_min_length: int = 16
    entropy_min_bits: float = 3.5
    min_unique_subdomains: int = 3
    min_uniqueness_ratio: float = 0.8
    burst_queries: int = 5
    burst_seconds: float = 15
    min_nxdomain_responses: int = 4
    min_nxdomain_ratio: float = 0.8
    full_qname_length: int = 100
    subdomain_labels: int = 5
    unusual_type_queries: int = 10

    def __post_init__(self):
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be numeric")
            if not 0 < value < float("inf"):
                raise ValueError(f"{name} must be finite and positive")
        for name in ("min_uniqueness_ratio", "min_nxdomain_ratio"):
            if getattr(self, name) > 1:
                raise ValueError(f"{name} must be at most 1")


class B1Detector:
    def __init__(self, configuration="expanded", thresholds=None,
                 cooldown_seconds=60, severity="MEDIUM"):
        configuration = configuration.lower()
        if configuration not in ("core", "expanded"):
            raise ValueError("configuration must be 'core' or 'expanded'")
        if not 0 <= cooldown_seconds < float("inf"):
            raise ValueError("cooldown_seconds must be finite and nonnegative")
        if severity not in ("MEDIUM", "HIGH"):
            raise ValueError("severity must be MEDIUM or HIGH")
        self.configuration = configuration
        self.rule_ids = CORE_RULES if configuration == "core" else EXPANDED_RULES
        self.thresholds = thresholds or B1Thresholds()
        self.cooldown_seconds = cooldown_seconds
        self.severity = severity
        self.histories = {}
        self.incidents = {}
        self.last_cleanup = None

    def _prune(self, history, now):
        retention = max(self.thresholds.window_seconds, self.thresholds.burst_seconds)
        while history and now - history[0]["time"] > retention:
            history.popleft()

    def _cleanup(self, now):
        if self.last_cleanup is not None and now - self.last_cleanup < 5:
            return
        self.last_cleanup = now
        for key in list(self.histories):
            self._prune(self.histories[key], now)
            if not self.histories[key]:
                del self.histories[key]
        for key in list(self.incidents):
            if now - self.incidents[key]["last_trigger"] > self.cooldown_seconds:
                del self.incidents[key]

    def observe(self, client_ip, domain, query_type, response_code, status, now=None):
        """Return an alert/incident update, or None; query_type is a numeric code.

        Live time is monotonic. The optional now is also monotonic, never UTC.
        Parent queries count in denominators but never as distinct subdomains.
        Root, unknown suffixes and names with no registered domain are skipped.
        """
        timestamp = monotonic() if now is None else now
        self._cleanup(timestamp)
        if status not in ("FORWARDED", "LOCAL", "LOCAL_TEST"):
            return None
        if response_code not in ("NOERROR", "NXDOMAIN"):
            return None
        if isinstance(query_type, bool) or not isinstance(query_type, int) or not 0 <= query_type <= 65535:
            raise ValueError("query_type must be a numeric DNS type from 0 to 65535")
        domain = domain.lower().rstrip(".")
        parts = EXTRACT(domain)
        if not (parts.domain and parts.suffix):
            return None
        parent = f"{parts.domain}.{parts.suffix}"
        key = (client_ip, parent)
        label = domain.split(".")[0]
        history = self.histories.setdefault(key, deque())
        history.append({
            "time": timestamp, "domain": domain, "subdomain": parts.subdomain,
            "label": label, "entropy": entropy(label), "qtype": query_type,
            "rcode": response_code,
        })
        self._prune(history, timestamp)
        t = self.thresholds
        items = [item for item in history if timestamp - item["time"] <= t.window_seconds]
        count = len(items)
        unique_count = len({item["subdomain"] for item in items if item["subdomain"]})
        unique_ratio = unique_count / count
        nx_count = sum(item["rcode"] == "NXDOMAIN" for item in items)
        nx_ratio = nx_count / count
        burst_count = sum(timestamp - item["time"] <= t.burst_seconds for item in history)
        longest_label = max(items, key=lambda item: len(item["label"]))
        entropy_candidates = [item for item in items if len(item["label"]) >= t.entropy_min_length]
        entropy_item = max(entropy_candidates, key=lambda item: item["entropy"], default=None)
        longest_name = max(items, key=lambda item: len(item["domain"]))
        deepest = max(items, key=lambda item: len(item["subdomain"].split(".")) if item["subdomain"] else 0)
        depth = len(deepest["subdomain"].split(".")) if deepest["subdomain"] else 0
        unusual = Counter(item["qtype"] for item in items
                          if item["qtype"] in (10, 16) or 65280 <= item["qtype"] <= 65534)
        unusual_count = sum(unusual.values())
        features = {
            "window_seconds": t.window_seconds, "query_count": count,
            "unique_subdomains": unique_count, "unique_ratio": unique_ratio,
            "max_label_length": len(longest_label["label"]),
            "max_label_entropy": max(item["entropy"] for item in items),
            "burst_seconds": t.burst_seconds, "queries_in_burst_window": burst_count,
            "nxdomain_count": nx_count, "nxdomain_ratio": nx_ratio,
            "max_qname_length": len(longest_name["domain"]),
            "max_subdomain_labels": depth, "unusual_type_queries": unusual_count,
            "unusual_type_counts": dict(unusual),
        }
        details = {}

        def trigger(rule_id, condition, values, explanation):
            if rule_id in self.rule_ids and condition:
                details[rule_id] = {"features": values, "reason": explanation}

        trigger("R1", len(longest_label["label"]) >= t.long_label_length,
                {"label_length": len(longest_label["label"]), "threshold": t.long_label_length,
                 "domain": longest_label["domain"]},
                f"Leftmost label has {len(longest_label['label'])} characters (>= {t.long_label_length}).")
        trigger("R2", entropy_item is not None and entropy_item["entropy"] >= t.entropy_min_bits,
                {"label_length": len(entropy_item["label"]) if entropy_item else 0,
                 "entropy": entropy_item["entropy"] if entropy_item else 0,
                 "min_length": t.entropy_min_length, "min_entropy": t.entropy_min_bits,
                 "domain": entropy_item["domain"] if entropy_item else None},
                f"A label of at least {t.entropy_min_length} characters has entropy "
                f"{entropy_item['entropy'] if entropy_item else 0:.3f} bits/character (>= {t.entropy_min_bits}).")
        trigger("R3", unique_count >= t.min_unique_subdomains and unique_ratio >= t.min_uniqueness_ratio,
                {"unique_subdomains": unique_count, "eligible_queries": count,
                 "unique_ratio": unique_ratio, "window_seconds": t.window_seconds,
                 "min_unique": t.min_unique_subdomains, "min_ratio": t.min_uniqueness_ratio},
                f"{unique_count} distinct subdomains / {count} eligible queries = {unique_ratio:.1%} "
                f"in {t.window_seconds}s (>= {t.min_unique_subdomains}, >= {t.min_uniqueness_ratio:.0%}).")
        trigger("R4", burst_count >= t.burst_queries,
                {"query_count": burst_count, "window_seconds": t.burst_seconds, "threshold": t.burst_queries},
                f"{burst_count} queries in {t.burst_seconds}s (>= {t.burst_queries}).")
        trigger("R5", nx_count >= t.min_nxdomain_responses and nx_ratio >= t.min_nxdomain_ratio,
                {"nxdomain_count": nx_count, "eligible_queries": count, "nxdomain_ratio": nx_ratio,
                 "window_seconds": t.window_seconds, "min_count": t.min_nxdomain_responses,
                 "min_ratio": t.min_nxdomain_ratio},
                f"{nx_count} NXDOMAIN / {count} eligible responses = {nx_ratio:.1%} in "
                f"{t.window_seconds}s (>= {t.min_nxdomain_responses}, >= {t.min_nxdomain_ratio:.0%}).")
        trigger("R6", len(longest_name["domain"]) >= t.full_qname_length,
                {"qname_length": len(longest_name["domain"]), "domain": longest_name["domain"],
                 "threshold": t.full_qname_length},
                f"Normalized QNAME has {len(longest_name['domain'])} characters, excluding trailing dot "
                f"(>= {t.full_qname_length}).")
        trigger("R7", depth >= t.subdomain_labels,
                {"subdomain_labels": depth, "domain": deepest["domain"], "threshold": t.subdomain_labels},
                f"{depth} subdomain labels below {parent} (>= {t.subdomain_labels}).")
        trigger("R8", unusual_count >= t.unusual_type_queries,
                {"query_count": unusual_count, "numeric_type_counts": dict(unusual),
                 "window_seconds": t.window_seconds, "threshold": t.unusual_type_queries},
                f"{unusual_count} TXT (16), NULL (10), or private-use (65280-65534) queries "
                f"in {t.window_seconds}s (>= {t.unusual_type_queries}).")
        if not details:
            self.incidents.pop(key, None)
            return None

        incident = self.incidents.get(key)
        is_new = incident is None or timestamp - incident["last_trigger"] > self.cooldown_seconds
        if is_new:
            incident = {"id": uuid4().hex, "details": {}, "last_trigger": timestamp}
            self.incidents[key] = incident
        added_rules = set(details) - set(incident["details"])
        incident["details"].update(details)
        incident["last_trigger"] = timestamp
        triggered_rules = [rule for rule in self.rule_ids if rule in incident["details"]]
        features["active_rule_ids"] = list(details)
        return {
            "client_ip": client_ip, "domain": parent, "detector": "B1",
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "severity": self.severity, "configuration": self.configuration,
            "triggered_rules": triggered_rules, "features": features,
            "rule_details": dict(incident["details"]),
            "reasons": [f"{rule}: {incident['details'][rule]['reason']}" for rule in triggered_rules],
            "incident_id": incident["id"], "new_incident": is_new,
            "new_rules": [rule for rule in self.rule_ids if rule in added_rules],
        }
