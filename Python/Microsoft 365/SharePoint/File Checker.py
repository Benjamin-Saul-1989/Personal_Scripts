#!/usr/bin/env python3
"""
sharepoint_scan.py
------------------
Scans a folder (recursively) for filenames that are incompatible
with SharePoint / OneDrive, reports issues, and optionally renames them.

Usage:
    python3 sharepoint_scan.py /path/to/folder
    python3 sharepoint_scan.py /path/to/folder --rename   # auto-rename without prompt
    python3 sharepoint_scan.py /path/to/folder --dry-run  # report only, no renaming
"""

import os
import re
import sys
import csv
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# SharePoint rules
# ---------------------------------------------------------------------------

# Characters not allowed in SharePoint/OneDrive file or folder names
BAD_CHARS = re.compile(r'[~"#%&*:<>?/\\{|}]')

# Windows reserved names (also blocked by SharePoint)
RESERVED = re.compile(
    r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..+)?$',
    re.IGNORECASE
)

# SharePoint max path length (relative to the document library root)
MAX_PATH = 400

# Friendly descriptions for each issue type
ISSUE_LABELS = {
    'bad_chars':      lambda d: f"Illegal character(s): {d}",
    'reserved':       lambda d: f"Reserved filename: {d}",
    'leading_space':  lambda _: "Starts with a space",
    'trailing_space': lambda _: "Ends with a space",
    'leading_dot':    lambda _: "Starts with a dot",
    'trailing_dot':   lambda _: "Ends with a dot",
    'multi_space':    lambda _: "Multiple consecutive spaces",
    'too_long':       lambda d: f"Path too long ({d} chars, max {MAX_PATH})",
}

# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def diagnose(name: str) -> list[dict]:
    """Return a list of issue dicts for a single filename."""
    issues = []

    bad = sorted(set(BAD_CHARS.findall(name)))
    if bad:
        issues.append({'type': 'bad_chars', 'detail': ' '.join(bad)})

    base = re.sub(r'\.[^.]+$', '', name)
    if RESERVED.match(base):
        issues.append({'type': 'reserved', 'detail': base.upper()})

    if name.startswith(' '):
        issues.append({'type': 'leading_space', 'detail': ''})
    if name.endswith(' '):
        issues.append({'type': 'trailing_space', 'detail': ''})
    if name.startswith('.'):
        issues.append({'type': 'leading_dot', 'detail': ''})
    if name.endswith('.'):
        issues.append({'type': 'trailing_dot', 'detail': ''})
    if re.search(r' {2,}', name):
        issues.append({'type': 'multi_space', 'detail': ''})

    return issues


def autofix(name: str) -> str:
    """Return a SharePoint-safe version of the filename."""
    f = name.strip()                        # remove leading/trailing spaces
    f = re.sub(r'^\.+', '', f)              # remove leading dots
    f = f.replace('&', 'and')              # & -> and  (keeps names readable)
    f = BAD_CHARS.sub('_', f)              # replace remaining bad chars with _
    f = re.sub(r' +', ' ', f)              # collapse multiple spaces
    f = f.rstrip('.')                       # remove trailing dots

    # Handle reserved names by prefixing with underscore
    base = re.sub(r'\.[^.]+$', '', f)
    ext  = f[len(base):]
    if RESERVED.match(base):
        f = '_' + f

    return f


def format_issues(issues: list[dict]) -> str:
    """Turn a list of issue dicts into a human-readable string."""
    parts = []
    for i in issues:
        label_fn = ISSUE_LABELS.get(i['type'], lambda d: i['type'])
        parts.append(label_fn(i['detail']))
    return '; '.join(parts)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan(root: str) -> list[dict]:
    """
    Walk the directory tree and return a list of result dicts, one per
    file or folder, including both clean and problematic entries.
    """
    root_path = Path(root).resolve()
    rows = []

    for dirpath, dirs, files in os.walk(root_path):
        # Check folders and files
        for name in dirs + files:
            full_path = Path(dirpath) / name
            rel_path  = full_path.relative_to(root_path)

            issues = diagnose(name)

            # Check overall path length separately
            path_too_long = len(str(rel_path)) > MAX_PATH
            if path_too_long:
                issues.append({
                    'type':   'too_long',
                    'detail': str(len(str(rel_path)))
                })

            fixed = autofix(name) if issues else name

            rows.append({
                'path':           str(rel_path),
                'original':       name,
                'issues':         format_issues(issues) if issues else 'OK',
                'suggested_name': fixed,
                'is_dir':         full_path.is_dir(),
            })

    # Sort: problems first, then alphabetically by path
    rows.sort(key=lambda r: (r['issues'] == 'OK', r['path']))
    return rows


# ---------------------------------------------------------------------------
# Renaming
# ---------------------------------------------------------------------------

def rename_all(root: str, rows: list[dict]) -> int:
    """
    Rename files and folders that need fixing.
    Processes deepest paths first to avoid breaking parent references.
    Returns the count of items renamed.
    """
    root_path = Path(root).resolve()
    to_rename = [r for r in rows if r['original'] != r['suggested_name']]

    # Rename deepest paths first (avoids renaming a parent before its children)
    to_rename.sort(key=lambda r: r['path'].count(os.sep), reverse=True)

    count = 0
    for r in to_rename:
        old_full = root_path / r['path']
        new_full = old_full.parent / r['suggested_name']

        if not old_full.exists():
            print(f"  [SKIP]    {r['path']}  (already moved or missing)")
            continue
        if new_full.exists():
            print(f"  [SKIP]    {r['original']} → {r['suggested_name']}  (target already exists)")
            continue

        try:
            old_full.rename(new_full)
            print(f"  [RENAMED] {r['original']}")
            print(f"         →  {r['suggested_name']}")
            count += 1
        except OSError as e:
            print(f"  [ERROR]   {r['path']}: {e}")

    return count


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(rows: list[dict]) -> None:
    """Print a summary of issues to stdout."""
    bad = [r for r in rows if r['issues'] != 'OK']
    ok  = [r for r in rows if r['issues'] == 'OK']

    print(f"\n{'='*60}")
    print(f"  SharePoint Filename Scan Report")
    print(f"{'='*60}")
    print(f"  Total items scanned : {len(rows)}")
    print(f"  Issues found        : {len(bad)}")
    print(f"  Clean               : {len(ok)}")
    print(f"{'='*60}\n")

    if not bad:
        print("  All filenames are SharePoint-compatible!\n")
        return

    for r in bad:
        kind = "FOLDER" if r['is_dir'] else "FILE  "
        print(f"  [{kind}] {r['path']}")
        print(f"           Issues  : {r['issues']}")
        if r['original'] != r['suggested_name']:
            print(f"           Rename  : {r['original']}")
            print(f"                  → {r['suggested_name']}")
        print()


def save_csv(rows: list[dict], output_path: str = 'sharepoint_scan_report.csv') -> None:
    """Save the full results to a CSV file."""
    fields = ['path', 'original', 'issues', 'suggested_name']
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    print(f"  Report saved to: {output_path}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Scan and fix filenames for SharePoint/OneDrive compatibility.'
    )
    parser.add_argument(
        'folder',
        nargs='?',
        default='.',
        help='Folder to scan (default: current directory)'
    )
    parser.add_argument(
        '--rename',
        action='store_true',
        help='Auto-rename without prompting'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Report issues only, do not rename anything'
    )
    parser.add_argument(
        '--csv',
        metavar='FILE',
        default='sharepoint_scan_report.csv',
        help='Path for the CSV report (default: sharepoint_scan_report.csv)'
    )

    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        print(f"Error: '{args.folder}' is not a directory.")
        sys.exit(1)

    print(f"\nScanning: {os.path.abspath(args.folder)}")
    rows = scan(args.folder)

    print_report(rows)
    save_csv(rows, args.csv)

    bad = [r for r in rows if r['issues'] != 'OK']
    needs_rename = [r for r in bad if r['original'] != r['suggested_name']]

    if not needs_rename:
        print("  Nothing to rename.")
        return

    if args.dry_run:
        print("  Dry run mode — no files were renamed.")
        return

    if args.rename:
        # Auto-rename without asking
        count = rename_all(args.folder, rows)
        print(f"\n  Done. {count} item(s) renamed.")
    else:
        # Interactive prompt
        answer = input(
            f"  Rename {len(needs_rename)} item(s) now? [y/N] "
        ).strip().lower()
        if answer == 'y':
            count = rename_all(args.folder, rows)
            print(f"\n  Done. {count} item(s) renamed.")
        else:
            print("  No changes made. Review the CSV report and re-run when ready.")


if __name__ == '__main__':
    main()