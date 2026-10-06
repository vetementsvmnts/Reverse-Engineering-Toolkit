from rekit.core.engine import RekitEngine
import json

engine = RekitEngine('samples/thefirsttest')
report = engine.solve()
print(json.dumps(report, indent=2))
