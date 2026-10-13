"""
Hex constant decoder.

Scans disassembled instructions for mov reg, 0x<hex> patterns
and decodes the immediate value as a Little Endian ASCII string.
Useful for finding passwords that are assembled at runtime
from hex constants.
"""
import re
import string


HEX_PATTERN = re.compile(r"0x([0-9a-fA-F]{8,16})")


def _looks_like_ascii(data: bytes) -> bool:
    """Check if a byte string is likely printable ASCII."""
    if not data:
        return False
    printable = set(string.printable.encode())
    printable_count = sum(1 for b in data if b in printable and b >= 0x20)
    return printable_count / len(data) > 0.7


def decode_hex_to_ascii(hex_str: str) -> list[str]:
    """
    Decode a hex immediate value to possible ASCII strings.

    Handles two byte orders:
      - Big Endian (network order): the ASCII reads left-to-right
      - Little Endian (x86): the bytes are reversed

    Returns a list of candidate strings (deduplicated).
    """
    hex_str = hex_str.replace("0x", "").strip()

    # Pad to even length
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str

    try:
        raw_bytes = bytes.fromhex(hex_str)
    except ValueError:
        return []

    candidates = []

    # Attempt 1: Big Endian (left-to-right)
    if _looks_like_ascii(raw_bytes):
        candidates.append(raw_bytes.decode("ascii", errors="ignore"))

    # Attempt 2: Little Endian (x86-style, bytes reversed)
    reversed_bytes = raw_bytes[::-1]
    if _looks_like_ascii(reversed_bytes):
        s = reversed_bytes.decode("ascii", errors="ignore")
        if s not in candidates:
            candidates.append(s)

    return candidates


def extract_hex_strings(instructions: list[dict]) -> list[dict]:
    """
    Scan disassembled instructions for hex immediates that decode to ASCII.

    Each instruction is a dict with keys: address, mnemonic, op_str.
    Returns a list of dicts with address, hex, and decoded strings.
    """
    findings = []

    for insn in instructions:
        # Only consider mov-like instructions
        if insn["mnemonic"] not in ("mov", "movabs", "movq"):
            continue

        # Look for hex immediates in the operand string
        for match in HEX_PATTERN.finditer(insn["op_str"]):
            hex_value = "0x" + match.group(1)
            decoded = decode_hex_to_ascii(hex_value)

            if decoded:
                findings.append({
                    "address": insn["address"],
                    "hex": hex_value,
                    "strings": decoded,
                })

    return findings
