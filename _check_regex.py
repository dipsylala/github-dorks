import yaml, re
from pathlib import Path

errors = []
pcre_only = []
total = 0

for f in sorted(Path('config/patterns').rglob('*.yaml')):
    with open(f, encoding='utf-8') as fh:
        data = yaml.safe_load(fh)
    lang = str(f.relative_to('config/patterns'))
    for p in data.get('patterns', []):
        total += 1
        pid = p.get('id', '?')
        regex = p.get('regex', '')
        try:
            re.compile(regex)
        except re.error as e:
            if '(?!' in regex or '(?<!' in regex or '(?<=' in regex or '(?=' in regex:
                pcre_only.append(f"  PCRE2-only  {lang} :: {pid}")
            else:
                errors.append(f"  BROKEN  {lang} :: {pid}  => {e}  REGEX={regex!r}")

if errors:
    print("=== BROKEN REGEX (will fail everywhere) ===")
    for e in errors:
        print(e)
else:
    print("No broken patterns found.")

if pcre_only:
    print("\n=== PCRE2-only (lookaheads: valid for rg --pcre2, not Python re) ===")
    for p in pcre_only:
        print(p)
else:
    print("No PCRE2-only patterns.")

print(f"\nTotal patterns checked: {total}")
