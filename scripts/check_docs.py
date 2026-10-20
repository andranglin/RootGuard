#!/usr/bin/env python3
"""Validate local Markdown links and SUMMARY.md file references without network access."""
from pathlib import Path
from urllib.parse import unquote
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'(?<!!)\[[^\]]*\]\((<?[^)]+>?)\)')
SKIP = ('http:', 'https:', 'mailto:', 'tel:', 'data:', '#')
errors = []
checked = 0

curated = [
    ROOT / 'README.md', ROOT / 'SUMMARY.md',
    *list((ROOT / 'start-here').rglob('*.md')),
    *list((ROOT / 'learning-paths').rglob('*.md')),
    *list((ROOT / 'security-architecture').rglob('*.md')),
    *list((ROOT / 'contributing').rglob('*.md')),
]
# All-articles mode supports progressive remediation of pre-existing legacy links.
pages = ROOT.rglob('*.md') if '--all' in sys.argv else curated
for page in pages:
    if '.git' in page.parts:
        continue
    content = page.read_text(encoding='utf-8')
    # Avoid false positives from fenced code examples.
    content = re.sub(r'(?ms)^\s*```.*?^\s*```\s*$', '', content)
    for match in LINK.finditer(content):
        target = match.group(1).strip().strip('<>').split(' ', 1)[0]
        if not target or target.startswith(SKIP):
            continue
        relative = unquote(target.split('#', 1)[0].split('?', 1)[0])
        if not relative:
            continue
        destination = (page.parent / relative).resolve()
        checked += 1
        try:
            destination.relative_to(ROOT)
        except ValueError:
            errors.append(f'{page.relative_to(ROOT)}: path escapes repository: {target}')
            continue
        if not destination.exists():
            errors.append(f'{page.relative_to(ROOT)}: broken link: {target}')

print(f'Checked {checked} internal links across Markdown files.')
if errors:
    for error in errors:
        print('ERROR:', error)
    print(f'{len(errors)} broken links found.')
    sys.exit(1)
print('No broken internal links detected.')
