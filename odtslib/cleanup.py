from __future__ import annotations

from pathlib import Path

from .config import PROJECT_ROOT, STAGED_ARTIFACTS


def remove_staged_files() -> list[Path]:
    removed: list[Path] = []
    for relative_path in STAGED_ARTIFACTS:
        path = PROJECT_ROOT / relative_path
        if path.is_file():
            path.unlink()
            removed.append(path)
    return removed

