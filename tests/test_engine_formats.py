from rekit.core.engine import RekitEngine

engine = RekitEngine('samples/thefirsttest')
formats = engine.get_format_strings()
for f in formats:
    print(f)
