from rekit.analysis.strings import extract_strings, categorize_strings

print("[*] Testing strings module...")
strings = extract_strings('samples/test_crackme')
print(f"[*] Extracted {len(strings)} strings.")

categories = categorize_strings(strings)
print(f"[*] Password-related: {categories['PASSWORD-RELATED']}")
print(f"[*] Other interesting: {categories['OTHER INTERESTING']}")
print("[*] Success!")

