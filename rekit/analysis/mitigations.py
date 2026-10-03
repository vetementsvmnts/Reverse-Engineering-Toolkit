"""
Security mitigations analysis (checksec-style).
"""
from pwn import ELF

def analyze_mitigations(filepath: str) -> dict:
    """Analyze an ELF binary for security mitigations."""
    try:
        elf = ELF(filepath, checksec=False)
        return {
            "Architecture":  elf.arch,
            "Bits":          elf.bits,
            "RELRO":         elf.relro,
            "Stack Canary":  elf.canary,
            "NX (No Exec)":  elf.nx,
            "PIE":           elf.pie,
            "Stripped":      elf.stripped,
            "Static":        elf.statically_linked,
        }
    except Exception as e:
        raise ValueError(f"Failed to analyze binary: {e}")
