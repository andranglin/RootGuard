#!/usr/bin/env python3
"""Review newly added public Markdown prose for em dashes and stock phrases.

Use with: python scripts/check_editorial.py --base origin/master
The check reads only added lines in the git diff. Existing legacy prose remains
a separate, tracked editorial backlog. Code blocks are ignored in whole-file mode.
"""
import argparse
import pathlib
import re
import subprocess
import sys

PHRASES = [
    "ever-evolving threat landscape", "cutting-edge", "game changer",
    "unlock the power of", "delve into", "seamlessly integrate",
    "in today's digital landscape",
]
PATTERN = re.compile("|".join(re.escape(p) for p in PHRASES), re.IGNORECASE)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="HEAD^")
    args = parser.parse_args()
    diff = subprocess.run(
        ["git", "diff", "--unified=0", args.base, "HEAD", "--", "*.md"],
        capture_output=True, text=True, check=True,
    ).stdout
    path = ""
    issues = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            if path == "contributing/README.md":
                continue
            added = line[1:]
            # Skip likely code, tables of technical syntax, or URL lines.
            if added.lstrip().startswith(("    ", "`", "http", "#!")):
                continue
            found = PATTERN.search(added)
            if "—" in added or found:
                issues.append((path, added[:180]))
    for path, excerpt in issues:
        print(f"Editorial review required: {path}: {excerpt}")
    if issues:
        print("Remove em dashes or stock language from newly added prose.")
        return 1
    print("New Markdown prose editorial checks passed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
