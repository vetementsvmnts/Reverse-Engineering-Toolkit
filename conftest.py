"""
Pytest configuration. Ensures the 'rekit' package is importable
when running tests from the project root.
"""
import sys
from pathlib import Path

# Add the project root directory to sys.path
sys.path.insert(0, str(Path(__file__).parent))
