from rekit.analysis.mitigations import analyze_mitigations

print("[*] Testing mitigations module...")
result = analyze_mitigations('samples/test_crackme')
print(result)
print("[*] Success!")
