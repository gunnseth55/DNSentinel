
from collections import defaultdict, deque
from time import monotonic
import  tldextract
extract_domain = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    extra_suffixes=("test",)
)
class DNSBehaviourDetector:

    def __init__(
        self,
        window_seconds=60,
        min_queries=5,
        min_unique=5,
        min_nxdomain_ratio=0.8,
        cooldown_seconds=60
    ):
        self.window_seconds = window_seconds
        self.min_queries = min_queries
        self.min_unique = min_unique
        self.min_nxdomain_ratio = min_nxdomain_ratio
        self.cooldown_seconds = cooldown_seconds

        self.histories = defaultdict(deque)
        self.last_alert = {}

    def analyze(self, client_ip, domain, response_code, now=None):

        domain = domain.lower().rstrip(".")

        parts = extract_domain(domain)

        # Only analyze domains containing a subdomain
        if not parts.domain or not parts.suffix or not parts.subdomain:
            return None
        
        parent_domain = f"{parts.domain}.{parts.suffix}"
        
        if response_code not in ("NOERROR", "NXDOMAIN"):
            return None

        if now is None:
            now = monotonic()

        key = (client_ip, parent_domain)
        history = self.histories[key]

        # Remember the latest request
        history.append((now, domain, response_code))

        # Remove requests older than the observation window
        while history and now - history[0][0] > self.window_seconds:
            history.popleft()

        count = len(history)

        unique_count = len({
            name for _, name, _ in history
        })

        nxdomain_count = sum(
            code == "NXDOMAIN"
            for _, _, code in history
        )

        nxdomain_ratio = nxdomain_count / count

        # Check behavioural detection conditions
        if (
            count < self.min_queries
            or unique_count < self.min_unique
            or nxdomain_ratio < self.min_nxdomain_ratio
        ):
            return None

        # Prevent repeated alerts within cooldown period
        previous_alert = self.last_alert.get(key)

        if (
            previous_alert is not None
            and now - previous_alert < self.cooldown_seconds
        ):
            return None

        self.last_alert[key] = now

        return {
            "domain": key[1],
            "risk": "HIGH",
            "score": 90,
            "reasons": [
                f"{unique_count} unique subdomains in "
                f"{self.window_seconds}s",
                f"NXDOMAIN ratio: {nxdomain_ratio:.0%} "
                f"({nxdomain_count}/{count})"
            ]
        }
