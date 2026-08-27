#!/usr/bin/env python3
"""Remove inline tailwind.config <script> blocks from templates safely.

Only removes a <script>...</script> block if it contains the literal
'tailwind.config' AND the block ends with '}' (no semicolon, which is
how the CDN config block is written). This avoids eating JS that follows.
"""
import re
import sys

FILES = [
    "templates/landing.html",
    "templates/auth.html",
    "templates/docs.html",
    "templates/models.html",
    "templates/status.html",
    "templates/dashboard.html",
    "templates/dashboard_user.html",
]

def remove_tailwind_config_blocks(content: str) -> tuple[str, int]:
    """Find <script> tags containing tailwind.config and remove only those."""
    # Split content by <script ...> ... </script> blocks
    pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL)

    def repl(match):
        inner = match.group(1)
        if 'tailwind.config' in inner:
            return ''  # drop whole script block
        return match.group(0)

    new_content, n = pattern.subn(repl, content)
    return new_content, n

def main():
    total = 0
    for f in FILES:
        with open(f, 'r', encoding='utf-8') as fh:
            content = fh.read()
        new_content, n = remove_tailwind_config_blocks(content)
        if n:
            with open(f, 'w', encoding='utf-8') as fh:
                fh.write(new_content)
            print(f"{f}: removed {n} tailwind config script block(s)")
            total += n
        else:
            print(f"{f}: no config script block found")
    print(f"\nTotal removed: {total}")

if __name__ == "__main__":
    main()
