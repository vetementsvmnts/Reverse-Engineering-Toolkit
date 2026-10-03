"""
CVE lookup via the NVD API.
"""
import os
from datetime import datetime, timedelta

try:
    import nvdlib
    NVD_AVAILABLE = True
except ImportError:
    NVD_AVAILABLE = False


def _severity_from_score(score) -> str:
    """Derive CVSS severity rating from a numeric score."""
    if score is None:
        return "UNKNOWN"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s == 0.0:
        return "NONE"
    if s < 4.0:
        return "LOW"
    if s < 7.0:
        return "MEDIUM"
    if s < 9.0:
        return "HIGH"
    return "CRITICAL"


def lookup_cve(keyword: str, limit: int = 5, years_back: int = 5) -> list[dict]:
    """
    Search the NVD for CVEs matching a keyword.

    Filters to CVEs published within the last `years_back` years.
    Returns a list of dicts with keys: id, score, severity, desc.
    """
    if not NVD_AVAILABLE:
        raise RuntimeError("nvdlib is not installed. Run: pip install nvdlib")

    api_key = os.environ.get("NVD_API_KEY")

    # NVD requires BOTH dates if you use either one.
    end_date = datetime.now()
    start_date = end_date - timedelta(days=365 * years_back)

    try:
        results = nvdlib.searchCVE(
            keywordSearch=keyword,
            key=api_key,
            limit=limit,
            pubStartDate=start_date,
            pubEndDate=end_date,
        )
    except Exception:
        # Fallback: search without date filter
        try:
            results = nvdlib.searchCVE(
                keywordSearch=keyword, key=api_key, limit=limit
            )
        except Exception as e:
            raise RuntimeError(f"NVD query failed: {e}")

    if not results:
        return []

    # Sort newest-first
    try:
        results = sorted(
            results,
            key=lambda c: getattr(c, "published", "") or "",
            reverse=True,
        )
    except Exception:
        pass

    cves = []
    for cve in results:
        score = (getattr(cve, "v31score", None)
                 or getattr(cve, "v30score", None)
                 or getattr(cve, "v2score", None))
        severity = (getattr(cve, "v31severity", None)
                    or getattr(cve, "v30severity", None))
        if not severity:
            severity = _severity_from_score(score)

        desc = cve.descriptions[0].value if cve.descriptions else "No description."
        cves.append({
            "id": cve.id,
            "score": score,
            "severity": severity,
            "desc": desc,
        })

    return cves
