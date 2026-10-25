#!/usr/bin/env python3
"""
Print the repository tree, the way the project documentation shows it.

    python scripts/generate_project_tree.py
    python scripts/generate_project_tree.py --max-depth 3
    python scripts/generate_project_tree.py --out docs/project-tree.md --check

Exists so that the tree in a document and the tree on disk can be compared
mechanically. A structure diagram in a README is the first thing to rot, and
nobody notices until somebody follows it to a file that moved.

`--check` regenerates into memory, diffs against the file, and exits non-zero
on a difference. That is the form CI runs.

What it ignores
---------------

Build output, caches, virtual environments, dependency directories and
anything `.gitignore`d by name, because a tree containing `node_modules` is a
tree nobody reads. The ignore list is explicit rather than read from
`.gitignore`, so the output does not change the moment somebody adds a line
there.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent

#: Directory names never shown.
IGNORE_DIRS = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "env",
    "htmlcov",
    "node_modules",
    "venv",
}

#: File suffixes and names never shown.
IGNORE_SUFFIXES = {".pyc", ".pyo", ".log", ".sqlite", ".sqlite3", ".db"}
IGNORE_FILES = {".DS_Store", "Thumbs.db"}

#: Directories whose contents are summarised rather than listed.
#:
#: Generated and imported data is the whole point of these two directories
#: being gitignored, so listing whatever happens to be in them today would
#: make the tree differ between machines.
SUMMARISE_DIRS = {"generated", "imports"}


def is_hidden_but_kept(name: str) -> bool:
    """
    Dotfiles worth showing. A repository's dotfiles are most of its configuration.
    """
    return name in {
        ".dockerignore",
        ".editorconfig",
        ".env.example",
        ".eslintrc.cjs",
        ".github",
        ".gitignore",
        ".gitkeep",
        ".nvmrc",
        ".pre-commit-config.yaml",
        ".prettierrc",
        ".python-version",
    }


def should_skip(path: Path) -> bool:
    name = path.name

    if path.is_dir():
        if name in IGNORE_DIRS:
            return True
        return name.startswith(".") and not is_hidden_but_kept(name)

    if name in IGNORE_FILES:
        return True

    if path.suffix in IGNORE_SUFFIXES:
        return True

    return name.startswith(".") and not is_hidden_but_kept(name)


def entries(directory: Path) -> list[Path]:
    """
    Directories first, then files, each alphabetically.

    Matches how the project tree is written in the documentation, and means
    the output is stable across filesystems that enumerate differently.
    """
    children = [child for child in directory.iterdir() if not should_skip(child)]
    return sorted(children, key=lambda p: (p.is_file(), p.name.lower()))


def render(
    directory: Path,
    *,
    prefix: str = "",
    depth: int = 0,
    max_depth: int | None = None,
) -> list[str]:
    lines: list[str] = []
    children = entries(directory)

    for index, child in enumerate(children):
        last = index == len(children) - 1
        connector = "└── " if last else "├── "

        if child.is_dir():
            lines.append(f"{prefix}{connector}{child.name}/")

            if child.name in SUMMARISE_DIRS:
                contents = [c for c in child.iterdir() if c.name != ".gitkeep"]
                extension = "    " if last else "│   "

                if contents:
                    lines.append(
                        f"{prefix}{extension}└── ({len(contents)} generated "
                        "file(s), gitignored)"
                    )
                else:
                    lines.append(f"{prefix}{extension}└── .gitkeep")

                continue

            if max_depth is not None and depth + 1 >= max_depth:
                continue

            lines.extend(
                render(
                    child,
                    prefix=prefix + ("    " if last else "│   "),
                    depth=depth + 1,
                    max_depth=max_depth,
                )
            )
        else:
            lines.append(f"{prefix}{connector}{child.name}")

    return lines


def build(root: Path, max_depth: int | None) -> str:
    lines = [f"{root.name}/"]
    lines.extend(render(root, max_depth=max_depth))
    return "\n".join(lines) + "\n"


def count_files(root: Path) -> tuple[int, int]:
    files = directories = 0

    for path in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if should_skip(path):
            continue

        if path.is_dir():
            directories += 1
        else:
            files += 1

    return files, directories


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print the repository tree as the documentation shows it.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="directory to walk (default: the repository root)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="stop descending at this depth",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write to this file instead of stdout",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="with --out, compare instead of writing and exit 1 on a difference",
    )
    parser.add_argument(
        "--fence",
        action="store_true",
        help="wrap the tree in a Markdown code fence",
    )
    parser.add_argument(
        "--count",
        action="store_true",
        help="also print the file and directory count",
    )
    args = parser.parse_args()

    if not args.root.is_dir():
        raise SystemExit(f"Not a directory: {args.root}")

    if args.check and not args.out:
        parser.error("--check needs --out")

    tree = build(args.root, args.max_depth)

    if args.count:
        files, directories = count_files(args.root)
        tree += f"\n{files} files, {directories} directories\n"

    text = f"```\n{tree}```\n" if args.fence else tree

    if not args.out:
        sys.stdout.write(text)
        return 0

    if args.check:
        if not args.out.exists():
            print(f"MISSING {args.out}")
            return 1

        current = args.out.read_text(encoding="utf-8")

        if current == text:
            print(f"OK: {args.out} matches the tree on disk")
            return 0

        print(f"DRIFTED {args.out}")
        diff = difflib.unified_diff(
            current.splitlines(keepends=True),
            text.splitlines(keepends=True),
            fromfile="on disk",
            tofile="generated",
            n=2,
        )
        sys.stdout.writelines(list(diff)[:60])
        print(f"\nRegenerate: python scripts/generate_project_tree.py --out {args.out}")
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
