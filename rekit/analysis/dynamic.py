"""
Dynamic analysis using strace and ltrace.
"""
import subprocess


def run_strace(filepath: str, timeout: int = 5) -> dict:
    """
    Run the binary under strace to capture system calls.
    Provides a dummy input to avoid immediate hangs on scanf/gets.
    """
    try:
        result = subprocess.run(
            ["strace", "-f", filepath],
            capture_output=True,
            text=True,
            timeout=timeout,
            input="test\n",  # Provide dummy input so it doesn't hang forever
        )
        return {
            "success": True,
            "output": result.stderr,  # strace writes to stderr
            "error": None,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "success": False,
            "output": e.stderr or "",
            "error": "Process timed out. It may be waiting for input.",
        }
    except FileNotFoundError:
        return {
            "success": False,
            "output": "",
            "error": "strace is not installed. Run: sudo apt install strace",
        }
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "error": str(e),
        }


def run_ltrace(filepath: str, timeout: int = 5) -> dict:
    """
    Run the binary under ltrace to capture library calls.
    This is incredibly useful for seeing strcmp, printf, scanf, etc.
    """
    try:
        result = subprocess.run(
            ["ltrace", "-f", filepath],
            capture_output=True,
            text=True,
            timeout=timeout,
            input="test\n",
        )
        return {
            "success": True,
            "output": result.stderr,
            "error": None,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "success": False,
            "output": e.stderr or "",
            "error": "Process timed out. It may be waiting for input.",
        }
    except FileNotFoundError:
        return {
            "success": False,
            "output": "",
            "error": "ltrace is not installed. Run: sudo apt install ltrace",
        }
    except Exception as e:
        return {
            "success": False,
            "output": "",
            "error": str(e),
        }
