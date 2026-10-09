"""
Command-line interface for the RE toolkit.
Developed By Kitsana Thuekoh
"""
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

from rekit.core.engine import RekitEngine

console = Console()

BANNER = r"""
[bold cyan]
 ██████╗ ███████╗██╗  ██╗██╗████████╗
 ██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝
 ██████╔╝█████╗  █████╔╝ ██║   ██║
 ██╔══██╗██╔══╝  ██╔═██╗ ██║   ██║
 ██║  ██║███████╗██║  ██╗██║   ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
[/bold cyan][dim]RE Toolkit v0.6.0 — Reporting Edition[/dim]
[bold yellow]Developed By Kitsana Thuekoh[/bold yellow]
"""

SUSPICIOUS_CALLS = (
    "strcmp", "strncmp", "memcmp", "strcpy", "strcat",
    "scanf", "printf", "puts", "gets", "fgets",
    "system", "exec", "popen", "ptrace",
    "open", "read", "write", "fopen",
)


def ask_path() -> str | None:
    path = Prompt.ask("[bold cyan]Enter path to binary[/bold cyan]").strip().strip("'\"")
    if not Path(path).exists():
        console.print(f"[red][!] File not found: {path}[/red]")
        return None
    return path


def show_file_info(engine: RekitEngine):
    info = engine.get_file_info()
    table = Table(title="File Info", title_style="bold magenta", header_style="bold cyan")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white", overflow="fold")
    for k, v in info.items():
        table.add_row(k, v)
    console.print(table)


def show_mitigations(engine: RekitEngine):
    mits = engine.get_mitigations()
    table = Table(title="Security Mitigations", title_style="bold magenta", header_style="bold cyan")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")
    for k, v in mits.items():
        v_str = (f"[green]{v}[/green]" if v else f"[red]{v}[/red]") if isinstance(v, bool) else str(v)
        table.add_row(k, v_str)
    console.print(table)


def show_strings(engine: RekitEngine):
    data = engine.get_strings()
    console.print(f"[*] Extracted [bold]{len(data['all'])}[/bold] strings.")
    for cat, items in data["categories"].items():
        if not items:
            continue
        lines = "\n".join(f"  [bold]->[/bold] {s}" for s in items)
        console.print(Panel(lines, title=f"[bold]{cat}[/bold]", border_style="cyan"))


def show_entropy(engine: RekitEngine):
    data = engine.get_entropy()
    table = Table(title="Entropy Analysis", title_style="bold magenta", header_style="bold cyan")
    table.add_column("Section", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Entropy", justify="right")
    table.add_column("Verdict", style="white")
    for r in data["sections"]:
        table.add_row(r["section"], f"{r['size']:,}", f"{r['entropy']:.3f}", r["verdict"])
    console.print(table)


def show_disassembly(engine: RekitEngine):
    data = engine.get_disassembly()
    if "error" in data:
        console.print(f"[red][!] {data['error']}[/red]")
        return

    console.print(f"[*] Disassembled [bold]{data['function']}[/bold]() — "
                  f"{len(data['instructions'])} instructions")

    comparisons = data["cmp_constants"]
    if comparisons:
        console.print("\n[bold yellow]=== Possible Integer Password Candidates ===[/bold yellow]")
        for c in comparisons:
            console.print(f"  [yellow]cmp[/yellow] {c['register']}, {c['hex']}   "
                          f"→  decimal: [bold]{c['decimal']}[/bold]")
    else:
        console.print("[dim]No immediate cmp constants found.[/dim]")


def show_solver(engine: RekitEngine):
    """Display the auto-solver report."""
    report = engine.solve()

    if report.get("error"):
        console.print(f"[red][!] Solver error: {report['error']}[/red]")
        return

    candidates = report.get("candidates", [])
    warnings = report.get("warnings", [])

    if not candidates:
        console.print("[yellow]No password candidates found.[/yellow]")
        return

    console.print("\n[bold yellow]=== AUTO-SOLVER RESULTS ===[/bold yellow]")
    for c in candidates:
        console.print(f"\n  [bold]Address:[/bold] {c['address']}")
        console.print(f"  [bold]Instruction:[/bold] cmp {c['register']}, {c['hex']}")
        console.print(f"  [bold]Format string:[/bold] {c['format']}")
        console.print(f"  [bold]Interpreted as:[/bold] {c['interpreted_as']}")
        console.print(f"  [bold green]→ Suggested password: {c['decimal']}[/bold green]")

    if warnings:
        console.print("\n[bold red]=== WARNINGS ===[/bold red]")
        for w in warnings:
            console.print(f"  [yellow]![/yellow] {w}")


def show_dynamic(engine: RekitEngine):
    console.print("\n[bold magenta]=== DYNAMIC ANALYSIS ===[/bold magenta]")

    console.print("\n[bold cyan]--- ltrace (library calls) ---[/bold cyan]")
    ltrace_result = engine.get_ltrace()
    if ltrace_result["error"]:
        console.print(f"[red][!] {ltrace_result['error']}[/red]")
    else:
        suspicious_lines = []
        for line in ltrace_result["output"].splitlines():
            if any(call in line for call in SUSPICIOUS_CALLS):
                suspicious_lines.append(f"[bold yellow]{line}[/bold yellow]")
            else:
                suspicious_lines.append(f"[dim]{line}[/dim]")

        for line in suspicious_lines[:40]:
            console.print(line)
        if len(suspicious_lines) > 40:
            console.print(f"[dim]... ({len(suspicious_lines) - 40} more lines)[/dim]")

    console.print("\n[bold cyan]--- strace (system calls, first 20) ---[/bold cyan]")
    strace_result = engine.get_strace()
    if strace_result["error"]:
        console.print(f"[red][!] {strace_result['error']}[/red]")
    else:
        for line in strace_result["output"].splitlines()[:20]:
            console.print(f"[dim]{line}[/dim]")


def show_decompiled(engine: RekitEngine):
    console.print("\n[bold magenta]=== DECOMPILATION (Radare2 pdc) ===[/bold magenta]")

    result = engine.get_decompiled("main")
    if result.get("error"):
        console.print(f"[red][!] {result['error']}[/red]")
        return

    console.print(f"\n[bold cyan]--- main() ---[/bold cyan]")
    console.print(result["code"])

    functions = engine.get_functions()
    if functions:
        console.print(f"\n[bold cyan]--- Detected Functions ({len(functions)}) ---[/bold cyan]")
        for f in functions:
            console.print(f"  [dim]{f['name']} (size: {f['size']})[/dim]")


def show_cve(engine: RekitEngine):
    keyword = Prompt.ask("[bold cyan]Enter software name or CVE keyword[/bold cyan]")
    try:
        cves = engine.get_cves(keyword, limit=5)
    except RuntimeError as e:
        console.print(f"[red][!] {e}[/red]")
        return

    if not cves:
        console.print(f"[yellow]No CVEs found for '{keyword}'.[/yellow]")
        return

    table = Table(title=f"CVEs matching: {keyword}", title_style="bold magenta",
                  header_style="bold cyan", show_lines=True)
    table.add_column("CVE ID", style="bold white")
    table.add_column("Score", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Description", overflow="fold")
    for cve in cves:
        sev = (cve["severity"] or "UNKNOWN").upper()
        color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "green"
        table.add_row(cve["id"], str(cve["score"] or "N/A"),
                      f"[{color}]{sev}[/{color}]", cve["desc"])
    console.print(table)


def full_analysis(engine: RekitEngine):
    show_file_info(engine)
    show_mitigations(engine)
    show_strings(engine)
    show_entropy(engine)
    show_disassembly(engine)
    show_solver(engine)


def menu():
    console.print(Panel(
        "[bold cyan]1[/bold cyan]  Full analysis\n"
        "[bold cyan]2[/bold cyan]  File info\n"
        "[bold cyan]3[/bold cyan]  Mitigations\n"
        "[bold cyan]4[/bold cyan]  Strings\n"
        "[bold cyan]5[/bold cyan]  Entropy\n"
        "[bold cyan]6[/bold cyan]  Disassembly (cmp constants)\n"
        "[bold cyan]7[/bold cyan]  CVE lookup\n"
        "[bold cyan]8[/bold cyan]  Auto-solver (find password)\n"
        "[bold cyan]9[/bold cyan]  Dynamic analysis (strace + ltrace)\n"
        "[bold cyan]10[/bold cyan] Decompile main (Radare2)\n"
        "[bold cyan]0[/bold cyan]  Exit",
        title="[bold magenta]RE Toolkit[/bold magenta]",
        border_style="magenta",
    ))

    choice = Prompt.ask("[bold cyan]Choose[/bold cyan]",
                        choices=[str(i) for i in range(11)], default="1")

    if choice == "0":
        console.print("[bold green]Goodbye![/bold green]")
        return False

    path = ask_path()
    if not path:
        return True

    engine = RekitEngine(path)

    try:
        if choice == "1":   full_analysis(engine)
        elif choice == "2": show_file_info(engine)
        elif choice == "3": show_mitigations(engine)
        elif choice == "4": show_strings(engine)
        elif choice == "5": show_entropy(engine)
        elif choice == "6": show_disassembly(engine)
        elif choice == "7": show_cve(engine)
        elif choice == "8": show_solver(engine)
        elif choice == "9": show_dynamic(engine)
        elif choice == "10": show_decompiled(engine)
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

    return True


def main():
    import argparse
    from rekit.utils.report import build_report, save_json

    parser = argparse.ArgumentParser(
        prog="rekit",
        description="Reverse Engineering Toolkit — Developed By Kitsana Thuekoh",
    )
    parser.add_argument("path", nargs="?", help="Path to the binary to analyze")
    parser.add_argument("--json", metavar="FILE", help="Save full report to JSON file")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    parser.add_argument("--verbose", action="store_true", help="Show everything")

    args = parser.parse_args()

    # ---- Non-interactive mode ----
    if args.path:
        if not Path(args.path).exists():
            console.print(f"[red][!] File not found: {args.path}[/red]")
            sys.exit(1)

        engine = RekitEngine(args.path)

        if args.json:
            try:
                report = build_report(engine)
                saved_to = save_json(report, args.json)
                if not args.quiet:
                    console.print(f"[green][+] Report saved to: {saved_to}[/green]")
            except Exception as e:
                console.print(f"[red][!] Failed to save JSON: {e}[/red]")

        if not args.quiet:
            full_analysis(engine)
        return

    # ---- Interactive mode ----
    console.print(BANNER)
    try:
        while menu():
            if not Confirm.ask("[bold cyan]Run another task?[/bold cyan]", default=True):
                break
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted.[/bold yellow]")


if __name__ == "__main__":
    main()
