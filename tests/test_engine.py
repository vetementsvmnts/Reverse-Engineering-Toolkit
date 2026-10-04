from rekit.core.engine import RekitEngine

print("[*] Testing core engine...")
engine = RekitEngine('samples/test_crackme')

print("\n--- File Info ---")
info = engine.get_file_info()
print(f"Size: {info['Size']}")

print("\n--- Mitigations ---")
mits = engine.get_mitigations()
print(f"PIE: {mits['PIE']}, Canary: {mits['Stack Canary']}")

print("\n--- Strings (categories) ---")
strings = engine.get_strings()
for cat, items in strings["categories"].items():
    if items:
        print(f"  {cat}: {items}")

print("\n--- Disassembly (cmp constants) ---")
disasm = engine.get_disassembly()
if "error" in disasm:
    print(f"  Error: {disasm['error']}")
else:
    for cmp in disasm["cmp_constants"]:
        print(f"  cmp {cmp['register']}, {cmp['hex']}  ->  {cmp['decimal']}")

print("\n[*] Success!")
