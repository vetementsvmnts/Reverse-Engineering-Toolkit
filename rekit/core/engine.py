"""
Core engine that orchestrates all analysis modules.
"""
from rekit.analysis.file_info import file_info
from rekit.analysis.mitigations import analyze_mitigations
from rekit.analysis.strings import extract_strings, categorize_strings
from rekit.analysis.entropy import entropy_analysis
from rekit.analysis.disassembly import disassemble_function, extract_cmp_constants
from rekit.analysis.cve import lookup_cve
from rekit.analysis.format_strings import find_format_strings
from rekit.analysis.dynamic import run_strace, run_ltrace
from rekit.analysis.radare import decompile_function, get_functions
from rekit.analysis.hex_strings import extract_hex_strings


class RekitEngine:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def get_file_info(self) -> dict:
        return file_info(self.filepath)

    def get_mitigations(self) -> dict:
        return analyze_mitigations(self.filepath)

    def get_strings(self) -> dict:
        all_strings = extract_strings(self.filepath)
        categories = categorize_strings(all_strings)
        return {"all": all_strings, "categories": categories}

    def get_entropy(self) -> dict:
        return entropy_analysis(self.filepath)

    def get_disassembly(self, function_name: str = "main") -> dict:
        try:
            instructions = disassemble_function(self.filepath, function_name)
            cmp_constants = extract_cmp_constants(instructions)
            return {
                "function": function_name,
                "instructions": instructions,
                "cmp_constants": cmp_constants,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_format_strings(self) -> list:
        return find_format_strings(self.filepath)

    def get_hex_strings(self) -> list:
        """Extract ASCII strings hidden inside hex constants in main()."""
        try:
            instructions = disassemble_function(self.filepath, "main")
            return extract_hex_strings(instructions)
        except Exception:
            return []

    def get_cves(self, keyword: str, limit: int = 5) -> list:
        return lookup_cve(keyword, limit=limit)

    def get_strace(self, timeout: int = 5) -> dict:
        return run_strace(self.filepath, timeout=timeout)

    def get_ltrace(self, timeout: int = 5) -> dict:
        return run_ltrace(self.filepath, timeout=timeout)

    def get_decompiled(self, function_name: str = "main") -> dict:
        return decompile_function(self.filepath, function_name)

    def get_functions(self) -> list:
        return get_functions(self.filepath)

    def solve(self, function_name: str = "main") -> dict:
        """
        Attempt to auto-solve a crackme by combining:
          - cmp constants from the disassembly
          - format strings from .rodata
          - hex constants that decode to ASCII
        Returns a dict with candidates and warnings.
        """
        result = {
            "function": function_name,
            "candidates": [],
            "warnings": [],
            "error": None,
        }

        try:
            disasm = self.get_disassembly(function_name)
            formats = self.get_format_strings()
            hex_strings = self.get_hex_strings()
            cmp_constants = disasm.get("cmp_constants", [])
        except Exception as e:
            result["error"] = str(e)
            return result

        # Warn about the whitespace hang bug (\n in scanf format)
        for f in formats:
            if "\\n" in f["format"] or "\n" in f["format"]:
                result["warnings"].append(
                    "Format string contains '\\n' — the program may hang "
                    "at runtime. Append a non-whitespace character (e.g. 'x')."
                )
                break

        # --- Integer candidates (from cmp instructions) ---
        fmt = next((f for f in formats if f["specifier"] in ("%d", "%x")), None)
        for cmp in cmp_constants:
            result["candidates"].append({
                "type": "integer",
                "hex": cmp["hex"],
                "decimal": cmp["decimal"],
                "register": cmp["register"],
                "address": cmp["address"],
                "format": fmt["format"] if fmt else None,
                "interpreted_as": fmt["interpreted_as"] if fmt else "unknown",
                "suggested": str(cmp["decimal"]),
            })

        # --- String candidates (from hex constants in main) ---
        for h in hex_strings:
            for s in h["strings"]:
                result["candidates"].append({
                    "type": "string",
                    "hex": h["hex"],
                    "address": h["address"],
                    "string": s,
                    "format": "%s",
                    "interpreted_as": "string (from hex constant)",
                    "suggested": s,
                })

        # --- Concatenated string candidate ---
        # If 2+ hex strings are found, join the LAST decoded version of each
        # (usually Little Endian), which often reconstructs the full password.
        if len(hex_strings) >= 2:
            parts = [h["strings"][-1] for h in hex_strings if h["strings"]]
            if len(parts) >= 2:
                joined = "".join(parts)
                result["candidates"].append({
                    "type": "joined_string",
                    "hex": " + ".join(h["hex"] for h in hex_strings),
                    "address": hex_strings[0]["address"],
                    "string": joined,
                    "format": "%s",
                    "interpreted_as": "concatenated string",
                    "suggested": joined,
                    "note": "Concatenation of all decoded hex constants",
                })

        return result
