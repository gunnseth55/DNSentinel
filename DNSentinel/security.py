
import math
from collections import Counter


def calculate_entropy(text):
    """Calculate Shannon entropy in bits per character."""

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_dns_query(domain):
    """
    Baseline rule-based DNS analysis.

    Returns:
        risk: LOW, MEDIUM, or HIGH
        score: 0, 50, or 100
        entropy: calculated character entropy
        reasons: list of triggered rules
    """

    domain = domain.lower().rstrip(".")
    labels = domain.split(".")

    # Analyze the leftmost DNS label.
    label = labels[0]

    label_length = len(label)
    entropy = calculate_entropy(label)

    score = 0
    reasons = []

    # Rule 1: Long DNS label
    if label_length >= 30:
        score += 50
        reasons.append(
            f"Long DNS label ({label_length} characters)"
        )

    # Rule 2: High character entropy
    if label_length >= 16 and entropy >= 3.5:
        score += 50
        reasons.append(
            f"High character entropy ({entropy:.2f})"
        )

    if score >= 100:
        risk = "HIGH"
    elif score >= 50:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "domain": domain,
        "label_length": label_length,
        "entropy": round(entropy, 3),
        "score": score,
        "risk": risk,
        "reasons": reasons
    }
