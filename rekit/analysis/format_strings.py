"""
Format string detection (helps interpret input type).
"""
import re
from pwn import ELF

FORMAT_PATTERN = re.compile(rb"%[0-9]*[dxsclu]")


def find_format_strings(filepath: str) -> list[dict]:
    """
    Scan the .rodata section for printf/scanf format strings.
    Returns a list of dicts with the string and its interpreted type.
    """
    try:
        elf = ELF(filepath, checksec=False)
    except Exception as e:
        raise ValueError(f"Failed to parse ELF: {e}")

    rodata = None
    for section in elf.sections:
        if section.name == ".rodata":
            rodata = section.data()
            break

    if not rodata:
        return []

    findings = []
    for match in FORMAT_PATTERN.finditer(rodata):
        # Extract the raw bytes around the format string to get the full string
        start = rodata.rfind(b"\x00", 0, match.start()) + 1
        end = rodata.find(b"\x00", match.end())
        full_str = rodata[start:end].decode("ascii", errors="replace")

        spec = match.group().decode("ascii")
        if "d" in spec:
            interpreted = "decimal integer"
        elif "x" in spec:
            interpreted = "hexadecimal integer"
        elif "s" in spec:
            interpreted = "string"
        else:
            interpreted = "unknown"

        findings.append({
            "format": full_str,
            "specifier": spec,
            "interpreted_as": interpreted,
        })

    # Remove duplicates
    seen = set()
    unique = []
    for f in findings:
        key = f["format"]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
