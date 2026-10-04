from rekit.analysis.entropy import analyze_entropy, get_suspicious_sections

print("[*] Testing entropy module...")
results = analyze_entropy('samples/test_crackme')

print(f"[*] Analyzed {len(results)} sections.")
print()
print("Top 5 highest-entropy sections:")
for r in sorted(results, key=lambda x: x["entropy"], reverse=True)[:5]:
    print(f"  {r['section']:<20} {r['entropy']:.3f}  {r['verdict']}")

suspicious = get_suspicious_sections(results)
print()
print(f"[*] Suspicious sections (likely packed): {suspicious if suspicious else 'None'}")
print("[*] Success!")
