#!/usr/bin/env python3
"""
Reverse Engineering Toolkit (toolkit.py)
----------------------------------------
A beginner-friendly toolkit for analyzing ELF binaries on Kali Linux.
"""

import hashlib
import math
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from pwn import ELF, context

context.log_level = "error"

# --- Rich ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
except ImportError:
    print("Missing 'rich'. Install with: pip install rich")
    sys.exit(1)

try:
    import nvdlib
    NVD_AVAILABLE = True
except ImportError:
    NVD_AVAILABLE = False

console = Console()


BANNER = r"""
[bold cyan]
 ██████╗ ███████╗██╗  ██╗██╗████████╗
 ██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝
 ██████╔╝█████╗  █████╔╝ ██║   ██║
 ██╔══██╗██╔══╝  ██╔═██╗ ██║   ██║
 ██║  ██║███████╗██║  ██╗██║   ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
[/bold cyan][dim]Reverse Engineering Toolkit for Kali Linux[/dim]
"""


# ======================================================================
# 1. FILE INFO + HASHES
# ======================================================================

def file_info(filepath):
    """Basic file metadata: size, hashes."""
    p = Path(filepath)
    data = p.read_bytes()

    info = {
        "Path":     str(p.resolve()),
        "Size":     f"{len(data):,} bytes",
        "MD5":      hashlib.md5(data).hexdigest(),
        "SHA1":     hashlib.sha1(data).hexdigest(),
        "SHA256":   hashlib.sha256(data).hexdigest(),
    }

    table = Table(title="File Info", title_style="bold magenta",
                  header_style="bold cyan", show_lines=False)
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="white", overflow="fold")
    for k, v in info.items():
        table.add_row(k, v)
    console.print(table)


# ======================================================================
# 2. MITIGATIONS
# ======================================================================

def analyze_mitigations(filepath):
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
        console.print(f"[red][!] Failed to analyze binary: {e}[/red]")
        return {}


def render_mitigations(info):
    if not info:
        return
    table = Table(title="Security Mitigations", title_style="bold magenta",
                  header_style="bold cyan")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    for k, v in info.items():
        if isinstance(v, bool):
            v_str = f"[green]{v}[/green]" if v else f"[red]{v}[/red]"
        else:
            v_str = str(v)
        table.add_row(k, v_str)
    console.print(table)


# ======================================================================
# 3. ELF STRUCTURE (sections, segments, entry)
# ======================================================================

def elf_structure(filepath):
    try:
        elf = ELF(filepath, checksec=False)
    except Exception as e:
        console.print(f"[red][!] Failed to parse ELF: {e}[/red]")
        return

    meta = {
        "Entry point": hex(elf.entry),
        "Base address": hex(elf.address),
        "Sections": len(elf.sections),
        "Segments": len(elf.segments),
    }
    meta_table = Table(title="ELF Overview", title_style="bold magenta",
                       header_style="bold cyan")
    meta_table.add_column("Field", style="cyan")
    meta_table.add_column("Value", style="white")
    for k, v in meta.items():
        meta_table.add_row(k, str(v))
    console.print(meta_table)

    sec_table = Table(title="Sections", title_style="bold magenta",
                      header_style="bold cyan")
    sec_table.add_column("Name", style="cyan", no_wrap=True)
    sec_table.add_column("Address", style="white")
    sec_table.add_column("Size", style="white", justify="right")
    for s in elf.sections:
        sec_table.add_row(s.name, hex(s.header.sh_addr), hex(s.header.sh_size))
    console.print(sec_table)


# ======================================================================
# 4. IMPORTS / EXPORTS
# ======================================================================

def imports_exports(filepath):
    try:
        elf = ELF(filepath, checksec=False)
    except Exception:
        return

    imports = sorted(elf.plt.keys()) if hasattr(elf, "plt") else []
    got     = sorted(elf.got.keys()) if hasattr(elf, "got") else []
    exports = sorted(elf.symbols.keys()) if elf.symbols else []

    if imports or got:
        t = Table(title="Imported Functions (PLT/GOT)", title_style="bold magenta",
                  header_style="bold cyan")
        t.add_column("Function", style="cyan")
        for f in sorted(set(imports + got)):
            t.add_row(f)
        console.print(t)

    if exports and not elf.stripped:
        t = Table(title="Symbols / Exports", title_style="bold magenta",
                  header_style="bold cyan")
        t.add_column("Symbol", style="cyan")
        t.add_column("Address", style="white")
        for name, addr in sorted(elf.symbols.items()):
            t.add_row(name, hex(addr))
        console.print(t)


# ======================================================================
# 5. STRING EXTRACTION + CATEGORIZATION
# ======================================================================

def extract_strings(filepath, min_length=4):
    with open(filepath, "rb") as f:
        data = f.read()
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    return [s.decode("ascii", errors="replace") for s in re.findall(pattern, data)]


def categorize_strings(strings):
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


def render_categories(categories):
    colors = {
        "FLAGS":             "yellow",
        "PASSWORD-RELATED":  "red",
        "USERNAME-RELATED":  "cyan",
        "URLs / EMAILS":     "green",
        "SOFTWARE BANNERS":  "magenta",
        "OTHER INTERESTING": "blue",
    }
    any_found = False
    for name, items in categories.items():
        if not items:
            continue
        any_found = True
        color = colors.get(name, "white")
        lines = "\n".join(f"  [bold {color}]->[/bold {color}] {item}" for item in items)
        console.print(Panel(lines, title=f"[bold {color}]{name}[/bold {color}]",
                            border_style=color))
    if not any_found:
        console.print(Panel("[yellow]No interesting strings found.[/yellow]",
                            border_style="yellow"))


# ======================================================================
# 6. ENTROPY ANALYSIS (detect packing/encryption)
# ======================================================================

def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of a byte string (0-8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def entropy_analysis(filepath):
    try:
        elf = ELF(filepath, checksec=False)
    except Exception:
        return

    table = Table(title="Entropy Analysis (packing / encryption detector)",
                  title_style="bold magenta", header_style="bold cyan")
    table.add_column("Section", style="cyan", no_wrap=True)
    table.add_column("Size", justify="right")
    table.add_column("Entropy", justify="right")
    table.add_column("Verdict", style="white")

    suspicious = []
    for s in elf.sections:
        data = s.data()
        if not data:
            continue
        ent = shannon_entropy(data)
        if ent > 7.2:
            verdict = "[red]HIGH - likely packed/encrypted[/red]"
            suspicious.append(s.name)
        elif ent > 6.5:
            verdict = "[yellow]MEDIUM - possibly compressed[/yellow]"
        else:
            verdict = "[green]normal[/green]"
        table.add_row(s.name, f"{len(data):,}", f"{ent:.3f}", verdict)

    console.print(table)
    if suspicious:
        console.print(
            f"[bold red][!] Suspicious sections (high entropy): "
            f"{', '.join(suspicious)}[/bold red]"
        )
        console.print("[yellow]    This binary may be packed. Try running 'upx -d' or unpacking first.[/yellow]")


# ======================================================================
# 7. ANTI-DEBUG DETECTION
# ======================================================================

ANTIDEBUG_INDICATORS = {
    "ptrace":       "Traces/debugs processes (classic anti-debug)",
    "prctl":        "Can set PR_SET_DUMPABLE to block debugging",
    "getppid":      "Detects debugger by checking parent process",
    "sigaction":    "Can intercept signals from a debugger",
    "personality":  "Can disable ASLR or detect debuggers",
    "syscall":      "Direct syscalls (may bypass hooks)",
    "/proc/self":   "Reads /proc/self (common anti-debug trick)",
    "LD_PRELOAD":   "May manipulate dynamic linker",
    "TracerPid":    "Checks /proc/self/status for TracerPid",
    "gettimeofday": "Timing checks (detect single-stepping)",
}


def anti_debug_check(filepath):
    try:
        strings = extract_strings(filepath, min_length=3)
        elf = ELF(filepath, checksec=False)
        imports = set(elf.plt.keys()) | set(elf.got.keys())
    except Exception:
        return

    findings = []
    joined = "\n".join(strings)
    for key, reason in ANTIDEBUG_INDICATORS.items():
        if key in imports or key in joined:
            findings.append((key, reason))

    if findings:
        t = Table(title="Anti-Debug / Anti-Analysis Indicators",
                  title_style="bold magenta", header_style="bold cyan")
        t.add_column("Indicator", style="red", no_wrap=True)
        t.add_column("Why it matters", style="white")
        for k, r in findings:
            t.add_row(k, r)
        console.print(t)
    else:
        console.print(Panel("[green]No common anti-debug indicators detected.[/green]",
                            border_style="green"))


# ======================================================================
# 8. CVE LOOKUP
# ======================================================================

def _severity_from_score(score):
    """Derive CVSS severity rating from a numeric score (v3/v4 scale)."""
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


def lookup_cve(keyword, limit=5, years_back=5):
    """
    Search the NVD for CVEs matching a keyword.

    Filters to CVEs published within the last `years_back` years so you
    get modern results instead of ones from 1999. Falls back to an
    unfiltered search if the date-filtered call fails.
    """
    if not NVD_AVAILABLE:
        console.print("[red][!] nvdlib is not installed. Run: pip install nvdlib[/red]")
        return []

    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        console.print("[yellow][!] NVD_API_KEY not set. Using rate-limited public access.[/yellow]")

    # --- Try the date-filtered search first ---
    results = []
    try:
        start_date = datetime.now() - timedelta(days=365 * years_back)
        results = nvdlib.searchCVE(
            keywordSearch=keyword,
            key=api_key,
            limit=limit,
            pubStartDate=start_date,
        )
    except Exception as e:
        console.print(f"[yellow][!] Date-filtered search failed ({e}); retrying without filter…[/yellow]")
        try:
            results = nvdlib.searchCVE(
                keywordSearch=keyword, key=api_key, limit=limit
            )
        except Exception as e2:
            console.print(f"[red][!] NVD query failed: {e2}[/red]")
            return []

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
        cves.append({"id": cve.id, "score": score,
                     "severity": severity, "desc": desc})
    return cves


def render_cves(cves, keyword, years_back=5):
    if not cves:
        console.print(f"[yellow]No CVEs found for '{keyword}' (last {years_back} years).[/yellow]")
        console.print("[dim]Try a broader keyword (e.g. 'nginx', 'log4j', 'Apache 2.4').[/dim]")
        return
    table = Table(
        title=f"CVEs matching: {keyword} (newest first, last {years_back} years)",
        title_style="bold magenta", header_style="bold cyan", show_lines=True,
    )
    table.add_column("CVE ID", style="bold white", no_wrap=True)
    table.add_column("Score", justify="center", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Description", overflow="fold")
    for cve in cves:
        score = cve["score"] if cve["score"] is not None else "N/A"
        sev = (cve["severity"] or "UNKNOWN").upper()
        if sev in ("CRITICAL", "HIGH"):
            sev_col = f"[red]{sev}[/red]"
        elif sev == "MEDIUM":
            sev_col = f"[yellow]{sev}[/yellow]"
        elif sev == "LOW":
            sev_col = f"[green]{sev}[/green]"
        else:
            sev_col = f"[dim]{sev}[/dim]"
        table.add_row(cve["id"], str(score), sev_col, cve["desc"])
    console.print(table)


# ======================================================================
# ORCHESTRATION
# ======================================================================

def full_analysis(filepath):
    console.rule(f"[bold cyan]Analyzing: {filepath}[/bold cyan]")

    console.rule("[bold magenta]1/6 — File Info[/bold magenta]")
    file_info(filepath)

    console.rule("[bold magenta]2/6 — Security Mitigations[/bold magenta]")
    render_mitigations(analyze_mitigations(filepath))

    console.rule("[bold magenta]3/6 — ELF Structure[/bold magenta]")
    elf_structure(filepath)

    console.rule("[bold magenta]4/6 — Imports / Exports[/bold magenta]")
    imports_exports(filepath)

    console.rule("[bold magenta]5/6 — String Extraction[/bold magenta]")
    strings = extract_strings(filepath)
    console.print(f"[*] Extracted [bold]{len(strings)}[/bold] strings.")
    categories = categorize_strings(strings)
    render_categories(categories)

    console.rule("[bold magenta]6/6 — Entropy & Anti-Debug[/bold magenta]")
    entropy_analysis(filepath)
    anti_debug_check(filepath)

    banners = categories["SOFTWARE BANNERS"]
    if banners:
        console.rule("[bold magenta]CVE Lookup for Detected Software[/bold magenta]")
        for banner in banners:
            console.print(f"[*] Searching NVD for: [bold]{banner}[/bold]")
            render_cves(lookup_cve(banner, limit=3), banner)
            time.sleep(0.6)


# ======================================================================
# MENU
# ======================================================================

def ask_binary_path():
    path = Prompt.ask("[bold cyan]Enter path to binary[/bold cyan]")
    path = path.strip().strip("'\"")
    if not Path(path).exists():
        console.print(f"[red][!] File not found: {path}[/red]")
        return None
    return path


def menu():
    while True:
        console.print()
        console.print(Panel(
            "[bold cyan]1[/bold cyan]  Full analysis (everything)\n"
            "[bold cyan]2[/bold cyan]  File info + hashes\n"
            "[bold cyan]3[/bold cyan]  Security mitigations\n"
            "[bold cyan]4[/bold cyan]  ELF structure (sections/segments)\n"
            "[bold cyan]5[/bold cyan]  Imports / Exports / Symbols\n"
            "[bold cyan]6[/bold cyan]  String extraction\n"
            "[bold cyan]7[/bold cyan]  Entropy analysis (packing detector)\n"
            "[bold cyan]8[/bold cyan]  Anti-debug indicators\n"
            "[bold cyan]9[/bold cyan]  CVE lookup by keyword\n"
            "[bold cyan]0[/bold cyan]  Exit",
            title="[bold magenta]Main Menu[/bold magenta]",
            border_style="magenta",
        ))
        choice = Prompt.ask("[bold cyan]Choose an option[/bold cyan]",
                            choices=[str(i) for i in range(10)], default="1")

        if choice == "1":
            p = ask_binary_path()
            if p: full_analysis(p)
        elif choice == "2":
            p = ask_binary_path()
            if p: file_info(p)
        elif choice == "3":
            p = ask_binary_path()
            if p: render_mitigations(analyze_mitigations(p))
        elif choice == "4":
            p = ask_binary_path()
            if p: elf_structure(p)
        elif choice == "5":
            p = ask_binary_path()
            if p: imports_exports(p)
        elif choice == "6":
            p = ask_binary_path()
            if p:
                strings = extract_strings(p)
                console.print(f"[*] Extracted [bold]{len(strings)}[/bold] strings.")
                render_categories(categorize_strings(strings))
        elif choice == "7":
            p = ask_binary_path()
            if p: entropy_analysis(p)
        elif choice == "8":
            p = ask_binary_path()
            if p: anti_debug_check(p)
        elif choice == "9":
            kw = Prompt.ask("[bold cyan]Enter software name or CVE keyword[/bold cyan]")
            render_cves(lookup_cve(kw, limit=5), kw)
        elif choice == "0":
            console.print("[bold green]Goodbye![/bold green]")
            break

        if not Confirm.ask("[bold cyan]Run another task?[/bold cyan]", default=True):
            break


def main():
    console.print(BANNER)
    if not NVD_AVAILABLE:
        console.print("[yellow][!] Optional: pip install nvdlib (for CVE lookup)[/yellow]\n")
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if Path(target).exists():
            full_analysis(target)
        else:
            console.print(f"[red][!] File not found: {target}[/red]")
        return
    try:
        menu()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted. Exiting.[/bold yellow]")


if __name__ == "__main__":
    main()
