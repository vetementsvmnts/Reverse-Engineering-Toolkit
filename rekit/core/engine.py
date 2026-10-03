"""
Core engine - orchestrates all analysis modules.
"""
from rekit.analysis.mitigations import analyze_mitigations
from rekit.analysis.file_info import get_file_info
from rekit.analysis.strings import extract_strings, categorize_strings
from rekit.analysis.entropy import analyze_entropy, get_suspicious_sections
from rekit.analysis.cve import lookup_cve
from rekit.analysis.disassembly import disassemble_function, extract_cmp_constants


class RekitEngine:
    """Main orchestrator for the RE toolkit."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def run_full_analysis(self) -> dict:
        """Run every analysis module and return all findings."""
        return {
            "file_info":     self.get_file_info(),
            "mitigations":   self.get_mitigations(),
            "strings":       self.get_strings(),
            "entropy":       self.get_entropy(),
            "disassembly":   self.get_disassembly(),
        }

    def get_file_info(self) -> dict:
        return get_file_info(self.filepath)

    def get_mitigations(self) -> dict:
        return analyze_mitigations(self.filepath)

    def get_strings(self) -> dict:
        strings = extract_strings(self.filepath)
        return {
            "all":        strings,
            "categories": categorize_strings(strings),
        }

    def get_entropy(self) -> dict:
        results = analyze_entropy(self.filepath)
        return {
            "sections":   results,
            "suspicious": get_suspicious_sections(results),
        }

    def get_disassembly(self, function_name: str = "main") -> dict:
        try:
            instructions = disassemble_function(self.filepath, function_name)
            comparisons  = extract_cmp_constants(instructions)
            return {
                "function":     function_name,
                "instructions": instructions,
                "cmp_constants": comparisons,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_cves(self, keyword: str, limit: int = 5) -> list[dict]:
        return lookup_cve(keyword, limit=limit)

