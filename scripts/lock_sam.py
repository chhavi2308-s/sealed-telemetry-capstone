"""Normalize an isolated SAM pip freeze while preserving platform restrictions.

Run SAM_PYTHON -m pip freeze --all > sam-freeze.txt, then
python scripts/lock_sam.py sam-freeze.txt --output requirements-sam.lock.
Review dependency/platform changes and validate on Linux and Windows before commit.
"""

import argparse
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

WINDOWS_ONLY = {"pywin32", "pypiwin32", "pywin32-ctypes"}


def normalize(text: str) -> str:
    lines = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        requirement = Requirement(line)
        if canonicalize_name(requirement.name) in WINDOWS_ONLY:
            marker = 'sys_platform == "win32"'
            if requirement.marker:
                marker = f"({requirement.marker}) and {marker}"
            requirement.marker = None
            line = f"{requirement}; {marker}"
        lines.append(line)
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("freeze", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(normalize(args.freeze.read_text()), encoding="utf-8")
