from rekit.analysis.file_info import get_file_info

print("[*] Testing file_info module...")
info = get_file_info('samples/test_crackme')

for k, v in info.items():
    print(f"{k}: {v}")

print("[*] Success!")
