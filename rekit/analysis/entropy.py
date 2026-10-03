"""
Entropy analysis - detects packing / encryption.
"""
import math
from collections import Counter
from pwn import ELF

def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of a byte string (range 0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def analyze_entropy(filepath: str) -> list[dict]:
    """
    Calculate entropy for every ELF section.

    Returns a list of dicts:
      {"section": str, "size": int, "entropy": float, "verdict": str}
    """
    try:
        elf = ELF(filepath, checksec=False)
    except Exception as e:
        raise ValueError(f"Failed to parse ELF: {e}")

    results = []
    for s in elf.sections:
        data = s.data()
        if not data:
            continue
        ent = shannon_entropy(data)

        if ent > 7.2:
            verdict = "HIGH - likely packed/encrypted"
        elif ent > 6.5:
            verdict = "MEDIUM - possibly compressed"
        else:
            verdict = "normal"

        results.append({
            "section": s.name,
            "size": len(data),
            "entropy": ent,
            "verdict": verdict,
        })

    return results


def get_suspicious_sections(results: list[dict]) -> list[str]:
    """Return the names of sections with HIGH entropy."""
    return [r["section"] for r in results if r["verdict"].startswith("HIGH")]
