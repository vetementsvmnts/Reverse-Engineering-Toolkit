from rekit.analysis.disassembly import disassemble_function
from rekit.analysis.hex_strings import extract_hex_strings

instructions = disassemble_function('samples/muhemed/crackme', 'main')
findings = extract_hex_strings(instructions)

print(f"[*] Found {len(findings)} hex constants that decode to ASCII:\n")
for f in findings:
    print(f"  {f['address']}: {f['hex']}")
    for s in f['strings']:
        print(f"      -> \"{s}\"")
