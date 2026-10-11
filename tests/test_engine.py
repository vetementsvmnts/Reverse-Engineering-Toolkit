"""
Unit tests for the RekitEngine.
"""
import pytest
from rekit.core.engine import RekitEngine

# Path to our test crackme
SAMPLE = 'samples/thefirsttest'


def test_engine_initialization():
    """Test that the engine loads a file correctly."""
    engine = RekitEngine(SAMPLE)
    assert engine.filepath == SAMPLE


def test_mitigations():
    """Test that the engine can analyze security mitigations."""
    engine = RekitEngine(SAMPLE)
    mits = engine.get_mitigations()
    assert mits['Architecture'] == 'amd64'
    assert mits['PIE'] is False  # thefirsttest is not PIE
    assert mits['NX (No Exec)'] is True


def test_solve_thefirsttest():
    """Test that the auto-solver finds the correct integer password."""
    engine = RekitEngine(SAMPLE)
    report = engine.solve()
    
    # Ensure no errors occurred
    assert report['error'] is None
    
    # Ensure we found at least one candidate
    assert len(report['candidates']) > 0
    
    # Check that the first candidate matches our expected password
    first = report['candidates'][0]
    assert first['decimal'] == 1923855305
    assert first['hex'] == '0x72abb3c9'
    assert first['interpreted_as'] == 'decimal integer'


def test_format_strings():
    """Test that format strings are detected correctly."""
    engine = RekitEngine(SAMPLE)
    formats = engine.get_format_strings()
    assert any(f['specifier'] == '%d' for f in formats)
