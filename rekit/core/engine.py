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

    def get_cves(self, keyword: str, limit: int = 5) -> list:
        return lookup_cve(keyword, limit=limit)

    def solve(self, function_name: str = "main") -> dict:
        """
        Attempt to auto-solve a crackme by combining:
          - cmp constants from the disassembly
          - format strings from .rodata
        Returns a dict with candidates and any warnings.
        """
        result = {
            "function": function_name,
            "candidates": [],
            "warnings": [],
            "error": None,
        }

        try:
            disasm = self.get_disassembly(function_name)
            if "error" in disasm and disasm["error"]:
                result["error"] = disasm["error"]
                return result

            formats = self.get_format_strings()
            cmp_constants = disasm.get("cmp_constants", [])
        except Exception as e:
            result["error"] = str(e)
            return result

        # Find the most relevant format string (first one with %d/%x)
        fmt = None
        for f in formats:
            if f["specifier"] in ("%d", "%x"):
                fmt = f
                break

        # Warn about the whitespace hang bug (\n in scanf format)
        for f in formats:
            if "\\n" in f["format"] or "\n" in f["format"]:
                result["warnings"].append(
                    "Format string contains '\\n' — the program may hang "
                    "at runtime. Append a non-whitespace character (e.g. 'x')."
                )
                break

        # Build candidate passwords
        for cmp in cmp_constants:
            candidate = {
                "hex": cmp["hex"],
                "decimal": cmp["decimal"],
                "register": cmp["register"],
                "address": cmp["address"],
                "format": fmt["format"] if fmt else None,
                "interpreted_as": fmt["interpreted_as"] if fmt else "unknown",
            }
            result["candidates"].append(candidate)

        return result
