"""
Core engine that orchestrates all analysis modules.
"""
from rekit.analysis.file_info import file_info
from rekit.analysis.mitigations import analyze_mitigations
from rekit.analysis.strings import extract_strings, categorize_strings
from rekit.analysis.entropy import entropy_analysis
from rekit.analysis.disassembly import disassemble_function, extract_cmp_constants
from rekit.analysis.cve import lookup_cve


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

    def get_cves(self, keyword: str, limit: int = 5) -> list:
        return lookup_cve(keyword, limit=limit)
