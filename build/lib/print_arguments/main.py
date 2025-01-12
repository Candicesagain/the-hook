from __future__ import annotations

import argparse
import os
import re
from collections.abc import Sequence
from typing import Tuple, Pattern, List, Dict, Iterable
from functools import lru_cache

BLACKLIST = [
    b'BEGIN RSA PRIVATE KEY',
    b'BEGIN DSA PRIVATE KEY',
    b'BEGIN EC PRIVATE KEY',
    b'BEGIN OPENSSH PRIVATE KEY',
    b'BEGIN PRIVATE KEY',
    b'PuTTY-User-Key-File-2',
    b'BEGIN SSH2 ENCRYPTED PRIVATE KEY',
    b'BEGIN PGP PRIVATE KEY BLOCK',
    b'BEGIN ENCRYPTED PRIVATE KEY',
    b'BEGIN OpenVPN Static key V1',
]

HIPPO_REGEX = re.compile(r'hippo', re.IGNORECASE)


# @lru_cache(maxsize=1)
def _get_comment_tuples() -> List[Tuple[str, str]]:
    """Defines comment styles for supported languages."""
    return [
        ('#', ''),                    # e.g., Python, YAML
        ('//', ''),                   # e.g., Golang, JavaScript
        (r'/\*', r' *\*/'),           # e.g., C, Java
        ('--', ''),                   # e.g., SQL
        (r'<!--[# \t]*?', ' *?-->'),  # e.g., XML
        # Extend here for more languages
    ]


# @lru_cache(maxsize=1)
def _get_file_to_index_dict() -> Dict[str, int]:
    """Maps file extensions to the index of comment styles in _get_comment_tuples."""
    return {
        'yaml': 0,
        'py': 0,
        'sql': 3,
        'go': 1,
        'js': 1,
        'java': 2,
        'xml': 4,
        # Add more mappings for other languages
    }


def _get_allowlist_regexes_for_file(filename: str) -> Iterable[List[Pattern]]:
    """Fetches allowlist regexes specific to the file's language."""
    comment_tuples = _get_comment_tuples()
    _, ext = os.path.splitext(filename)
    ext = ext[1:]  # Strip the leading dot from the extension

    if ext in _get_file_to_index_dict():
        comment_tuples = [comment_tuples[_get_file_to_index_dict()[ext]]]

    yield [
        get_allowlist_regexes(comment_tuple=t, nextline=False)
        for t in comment_tuples
    ]
    yield [
        get_allowlist_regexes(comment_tuple=t, nextline=True)
        for t in comment_tuples
    ]


# @lru_cache(maxsize=12)
def get_allowlist_regexes(comment_tuple: Tuple[str, str], nextline: bool) -> Pattern:
    """Generates the allowlist regex for inline and nextline pragmas."""
    start = comment_tuple[0]
    end = comment_tuple[1]
    return re.compile(
        r'{}[ \t]*{} *pragma: ?{}{}[ -]secret.*?{}[ \t]*$'.format(
            r'^' if nextline else '',
            start,
            r'allowlist' if nextline else r'(allow|white)list',
            r'[ -]nextline' if nextline else '',
            end,
        ),
    )


def is_line_allowlisted(filename: str, line: str, context: CodeSnippet) -> bool:
    """Checks if a line is allowlisted."""
    for payload, regexes in zip(
        [line, context.previous_line],
        _get_allowlist_regexes_for_file(filename),
    ):
        for regex in regexes:
            if regex.search(payload):
                return True
    return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('filenames', nargs='*', help='Filenames to check')
    args = parser.parse_args(argv)

    flagged_files = []

    for filename in args.filenames:
        with open(filename, 'rb') as f:
            lines = f.readlines()

        file_flagged = False
        skip_next_line = False

        # Get allowlist regexes for the specific file type
        allowlist_regexes, nextline_allowlist_regexes = _get_allowlist_regexes_for_file(filename)

        for i, line in enumerate(lines, start=1):
            line_str = line.decode(errors="replace")

            if skip_next_line:
                skip_next_line = False
                continue

            # Check if the line is allowlisted for "nextline" pragma
            if any(regex.search(line_str) for regex in nextline_allowlist_regexes):
                skip_next_line = True
                continue

            # Check if the line is allowlisted for inline pragma
            if any(regex.search(line_str) for regex in allowlist_regexes):
                continue

            # Check for blacklist patterns or custom patterns (e.g., HIPPO_REGEX)
            if any(pattern in line for pattern in BLACKLIST) or HIPPO_REGEX.search(line_str):
                if not file_flagged:
                    print(f'Flagged content found in: {filename}')
                    flagged_files.append(filename)
                    file_flagged = True
                print(f'  Line {i}: {line_str.strip()}')

    return 1 if flagged_files else 0


if __name__ == '__main__':
    raise SystemExit(main())
