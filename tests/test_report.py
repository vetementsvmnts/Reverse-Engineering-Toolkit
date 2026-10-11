from rekit.core.engine import RekitEngine
from rekit.utils.report import build_report, save_json

engine = RekitEngine('samples/thefirsttest')
report = build_report(engine)
path = save_json(report, 'reports/thefirsttest.json')

print(f"[*] Report saved to: {path}")
print(f"[*] Total strings: {report['strings']['total']}")
print(f"[*] Password candidates: {len(report['solver']['candidates'])}")
