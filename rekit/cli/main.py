"""
Command-line interface for the RE toolkit.
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
[/bold cyan][dim]RE Toolkit v0.2.0 — Modular Edition[/dim]
"""


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


def menu():
    console.print(BANNER)
    console.print(Panel(
        "[bold cyan]1[/bold cyan]  Full analysis\n"
        "[bold cyan]2[/bold cyan]  File info\n"
        "[bold cyan]3[/bold cyan]  Mitigations\n"
        "[bold cyan]4[/bold cyan]  Strings\n"
        "[bold cyan]5[/bold cyan]  Entropy\n"
        "[bold cyan]6[/bold cyan]  Disassembly (cmp constants)\n"
        "[bold cyan]7[/bold cyan]  CVE lookup\n"
        "[bold cyan]0[/bold cyan]  Exit",
        title="[bold magenta]RE Toolkit[/bold magenta]",
        border_style="magenta",
    ))

    choice = Prompt.ask("[bold cyan]Choose[/bold cyan]",
                        choices=[str(i) for i in range(8)], default="1")

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
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

    return True


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if not Path(path).exists():
            console.print(f"[red][!] File not found: {path}[/red]")
            sys.exit(1)
        full_analysis(RekitEngine(path))
        return

    try:
        while menu():
            if not Confirm.ask("[bold cyan]Run another task?[/bold cyan]", default=True):
                break
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted.[/bold yellow]")


if __name__ == "__main__":
    main()
