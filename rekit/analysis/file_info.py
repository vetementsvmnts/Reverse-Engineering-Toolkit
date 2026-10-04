"""
File info and hashing.
"""
import hashlib
from pathlib import Path

def file_info(filepath: str) -> dict:
    """Return basic file metadata and hashes."""
    p = Path(filepath)
    data = p.read_bytes()

    return {
        "Path":     str(p.resolve()),
        "Size":     f"{len(data):,} bytes",
        "MD5":      hashlib.md5(data).hexdigest(),
        "SHA1":     hashlib.sha1(data).hexdigest(),
        "SHA256":   hashlib.sha256(data).hexdigest(),
    }
