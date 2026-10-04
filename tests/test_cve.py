from rekit.analysis.cve import lookup_cve

print("[*] Testing CVE module...")
print("[*] Searching NVD for 'nginx' (last 5 years)...")

cves = lookup_cve("nginx", limit=3)

if not cves:
    print("[!] No CVEs found (maybe rate-limited, try again in a bit).")
else:
    for cve in cves:
        print(f"\n{cve['id']}  [{cve['severity']}]  Score: {cve['score']}")
        print(f"  {cve['desc'][:100]}...")

print("\n[*] Success!")
