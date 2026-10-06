from rekit.analysis.format_strings import find_format_strings

result = find_format_strings('samples/thefirsttest')
for f in result:
    print(f)
