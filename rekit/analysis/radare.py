"""
Radare2 integration via r2pipe — for decompilation and advanced analysis.
"""
import r2pipe


def decompile_function(filepath: str, function_name: str = "main") -> dict:
    """
    Decompile a function using Radare2's pseudo-C decompiler (pdc).

    Returns a dict with the decompiled code or an error message.
    """
    r2 = None
    try:
        r2 = r2pipe.open(filepath, flags=["-2"])

        # Basic analysis (find functions)
        r2.cmd("aa")

        # Seek to the function and decompile it
        r2.cmd(f"s sym.{function_name}")
        decompiled = r2.cmd("pdc")

        if not decompiled or "Cannot" in decompiled:
            return {"error": f"Could not decompile {function_name}", "code": None}

        return {"error": None, "code": decompiled, "function": function_name}

    except FileNotFoundError:
        return {"error": "Radare2 is not installed. Run: sudo apt install radare2", "code": None}
    except Exception as e:
        return {"error": str(e), "code": None}
    finally:
        if r2:
            r2.quit()


def get_functions(filepath: str) -> list:
    """
    List all functions detected by Radare2's analysis.
    """
    r2 = None
    try:
        r2 = r2pipe.open(filepath, flags=["-2"])
        r2.cmd("aa")
        functions = r2.cmdj("aflj")

        if not functions:
            return []

        cleaned = []
        for f in functions:
            cleaned.append({
                "name": f.get("name", "unknown"),
                "size": f.get("size", 0),
                "offset": hex(f.get("offset", 0)),
            })
        return cleaned

    except FileNotFoundError:
        return []
    except Exception:
        return []
    finally:
        if r2:
            r2.quit()
