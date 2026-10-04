"""
Entropy analysis (packing detector).
"""
import math
from collections import Counter
from pwn import ELF

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def entropy_analysis(filepath: str) -> dict:
    """Return entropy for each section as raw data."""
    try:
        elf = ELF(filepath, checksec=False)
    except Exception:
        return {"sections": []}

    sections = []
    for s in elf.sections:
        data = s.data()
        if not data:
            continue
        ent = shannon_entropy(data)
        
        if ent > 7.2:
            verdict = "[red]HIGH - likely packed[/red]"
        elif ent > 6.5:
            verdict = "[yellow]MEDIUM - possibly compressed[/yellow]"
        else:
            verdict = "[green]normal[/green]"
            
        sections.append({
            "section": s.name,
            "size": len(data),
            "entropy": ent,
            "verdict": verdict
        })
        
    return {"sections": sections}
