"""
String extraction and categorization.
"""
import re

def extract_strings(filepath: str, min_length: int = 4) -> list[str]:
    """Return all printable ASCII strings from the binary."""
    with open(filepath, "rb") as f:
        data = f.read()
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    return [s.decode("ascii", errors="replace") for s in re.findall(pattern, data)]


def categorize_strings(strings: list[str]) -> dict:
    """Sort strings into buckets of interest."""
    categories = {
        "FLAGS":             [],
        "PASSWORD-RELATED":  [],
        "USERNAME-RELATED":  [],
        "URLs / EMAILS":     [],
        "SOFTWARE BANNERS":  [],
        "OTHER INTERESTING": [],
    }

    flag_pat  = re.compile(r"[A-Za-z0-9_]{2,12}\{[^}]+\}")
    url_pat   = re.compile(r"https?://[^\s]+")
    email_pat = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    sw_pat = re.compile(
        r"\b(OpenSSH|Apache|nginx|OpenSSL|PHP|Python|curl|wget|"
        r"FileZilla|ProFTPD|vsFTPd|Samba|MySQL|MariaDB|PostgreSQL|"
        r"Redis|MongoDB|Lighttpd|Tomcat|Jetty)[/_\- ]\d+[\.\d]*\w*",
        re.IGNORECASE,
    )

    pass_keys = ("pass", "pwd", "password")
    user_keys = ("user", "username", "login", "admin", "root")
    int_keys  = ("secret", "flag", "key", "token", "ctf", "correct",
                 "wrong", "denied", "granted", "success", "fail",
                 "congrat", "invalid", "error")

    seen = set()
    for s in strings:
        if s in seen:
            continue
        seen.add(s)
        low = s.lower()
        if flag_pat.search(s):
            categories["FLAGS"].append(s)
        elif sw_pat.search(s):
            categories["SOFTWARE BANNERS"].append(s)
        elif url_pat.search(s) or email_pat.search(s):
            categories["URLs / EMAILS"].append(s)
        elif any(k in low for k in pass_keys):
            categories["PASSWORD-RELATED"].append(s)
        elif any(k in low for k in user_keys):
            categories["USERNAME-RELATED"].append(s)
        elif any(k in low for k in int_keys):
            categories["OTHER INTERESTING"].append(s)
    return categories
