#!/usr/bin/env python3
"""Fail-closed secret, CJK, and upstream contamination scanner for agy-profiles."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable, List, Tuple

SCAN_EXTENSIONS = {
    ".py",
    ".rs",
    ".sh",
    ".js",
    ".css",
    ".html",
    ".svg",
    ".md",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
    ".txt",
}

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".venv",
    "dist",
    "build",
}

# Patterns are constructed defensively so this file never triggers self-matches.
RULES: List[Tuple[str, re.Pattern[str]]] = [
    ("github_token", re.compile(r"gh[pous]_[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(r"github_p" + r"at_[A-Za-z0-9_]{20,}")),
    ("google_api_key", re.compile(r"AI" + r"za[0-9A-Za-z_-]{30,}")),
    ("openai_like_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(r"xox[bpa]-[A-Za-z0-9-]{10,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRI" + r"VATE KEY-----")),
    ("cjk_character", re.compile(r"[\u4e00-\u9fff]")),
    ("upstream_brand", re.compile(r"para" + r"gravity", re.IGNORECASE)),
    ("upstream_org", re.compile(r"edison-" + r"land", re.IGNORECASE)),
    ("personal_home_path", re.compile(r"/Users/harry" + r"phan", re.IGNORECASE)),
    ("personal_email", re.compile(r"harry\.phan@" + r"commandoss\.com", re.IGNORECASE)),
]


def _iter_repo_files(repo_root: Path) -> Iterable[Path]:
    git_dir = repo_root / ".git"
    if git_dir.is_dir():
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            for rel in proc.stdout.splitlines():
                p = repo_root / rel.strip()
                if p.is_file() and (p.suffix in SCAN_EXTENSIONS or p.name in {"LICENSE", "agy-profiles", "agyp"}):
                    yield p
            return

    for path in sorted(repo_root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix in SCAN_EXTENSIONS or path.name in {"LICENSE", "agy-profiles", "agyp"}:
            yield path


def scan_repository(repo_root: Path) -> List[str]:
    """Scan repository files and return human-readable violation strings."""
    findings: List[str] = []
    for file_path in _iter_repo_files(repo_root):
        rel = str(file_path.relative_to(repo_root))
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule_name, pattern in RULES:
                if pattern.search(line):
                    findings.append("{}:{}: matched {}".format(rel, lineno, rule_name))
    return findings


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify agy-profiles repo has no secrets or banned artifacts.")
    parser.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repository root to inspect.",
    )
    args = parser.parse_args(argv)
    repo_root = Path(args.root).resolve()
    findings = scan_repository(repo_root)
    if findings:
        for item in findings:
            print("FAIL:", item, file=sys.stderr)
        return 1
    print("OK: 0 secret, CJK, personal-path, or upstream findings in {}".format(repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
