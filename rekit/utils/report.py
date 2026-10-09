"""
Report export utilities — save analysis results to JSON.
"""
import json
from datetime import datetime
from pathlib import Path


def save_json(data: dict, output_path: str) -> str:
    """
    Save a dictionary of results to a JSON file.
    Returns the path to the saved file.
    """
    payload = {
        "tool": "rekit",
        "generated_at": datetime.now().isoformat(),
        "results": data,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)

    return str(path)


def build_report(engine) -> dict:
    """
    Build a complete report by running every analysis module.
    Engine is a RekitEngine instance.
    """
    strings_data = engine.get_strings()
    report = {
        "file": engine.filepath,
        "file_info": engine.get_file_info(),
        "mitigations": engine.get_mitigations(),
        "strings": {
            "total": len(strings_data["all"]),
            "categories": strings_data["categories"],
        },
        "entropy": engine.get_entropy(),
        "disassembly": engine.get_disassembly(),
        "format_strings": engine.get_format_strings(),
        "solver": engine.solve(),
        "functions": engine.get_functions(),
    }
    return report
