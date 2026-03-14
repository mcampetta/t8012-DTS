from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .exceptions import DependencyError, ODTSError


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False


def _normalize_args(args: Sequence[str | Path]) -> list[str]:
    return [str(arg) for arg in args]


def format_command(args: Sequence[str | Path]) -> str:
    return " ".join(shlex.quote(str(arg)) for arg in args)


def run_command(
    args: Sequence[str | Path],
    *,
    cwd: str | Path | None = None,
    check: bool = True,
    capture_output: bool = True,
    dry_run: bool = False,
) -> CommandResult:
    normalized = _normalize_args(args)
    if dry_run:
        return CommandResult(normalized, 0, "", "", skipped=True)

    try:
        completed = subprocess.run(
            normalized,
            cwd=str(cwd) if cwd else None,
            check=False,
            capture_output=capture_output,
            text=True,
        )
    except FileNotFoundError as exc:
        raise DependencyError(f"Missing executable: {normalized[0]}") from exc
    except OSError as exc:
        raise ODTSError(f"Failed to execute command: {format_command(normalized)} ({exc})") from exc

    result = CommandResult(
        args=normalized,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    if check and completed.returncode != 0:
        raise ODTSError(
            f"Command failed with exit code {completed.returncode}: {format_command(normalized)}\n"
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result
