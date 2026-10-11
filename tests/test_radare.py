from rekit.analysis.radare import decompile_function, get_functions

print("=== FUNCTIONS DETECTED BY RADARE2 ===")
funcs = get_functions('samples/thefirsttest')
for f in funcs:
    print(f"  {f['offset']:>10}  {f['name']}  (size: {f['size']})")

print("\n=== DECOMPILED main() ===")
result = decompile_function('samples/thefirsttest', 'main')
if result["error"]:
    print(f"Error: {result['error']}")
else:
    print(result["code"])
