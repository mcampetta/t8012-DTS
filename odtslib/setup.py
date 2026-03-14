from __future__ import annotations

import json
import shutil
import stat
import tempfile
from pathlib import Path
from zipfile import ZipFile

import requests

from .config import FETCHABLE_RESOURCES, MANUAL_RESOURCES, PROJECT_ROOT


def _resource_exists(relative_path: str) -> bool:
    return (PROJECT_ROOT / relative_path).exists()


def inspect_setup_state() -> dict[str, object]:
    fetchable = []
    for name, item in FETCHABLE_RESOURCES.items():
        fetchable.append(
            {
                "name": name,
                "path": item["path"],
                "exists": _resource_exists(item["path"]),
                "url": item["url"],
                "note": item["note"],
                "auto_fetch_supported": True,
            }
        )

    manual = []
    for name, item in MANUAL_RESOURCES.items():
        manual.append(
            {
                "name": name,
                "path": item["path"],
                "exists": _resource_exists(item["path"]),
                "reason": item["reason"],
                "auto_fetch_supported": False,
            }
        )

    return {
        "fetchable_resources": fetchable,
        "manual_resources": manual,
    }


def _ensure_parent(relative_path: str) -> Path:
    destination = PROJECT_ROOT / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def _mark_executable(path: Path) -> None:
    current_mode = path.stat().st_mode
    path.chmod(current_mode | stat.S_IEXEC)


def _download_to_temp(url: str) -> Path:
    response = requests.get(url, allow_redirects=True, timeout=60)
    response.raise_for_status()
    temp_dir = Path(tempfile.mkdtemp(prefix="odts-setup-"))
    archive_path = temp_dir / "download.zip"
    archive_path.write_bytes(response.content)
    return archive_path


def fetch_missing_resources(*, dry_run: bool) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []

    for name, item in FETCHABLE_RESOURCES.items():
        destination = PROJECT_ROOT / item["path"]
        if destination.exists():
            continue

        action = {
            "name": name,
            "path": item["path"],
            "url": item["url"],
            "status": "planned" if dry_run else "fetched",
        }
        actions.append(action)
        if dry_run:
            continue

        archive_path = _download_to_temp(item["url"])
        try:
            with ZipFile(archive_path, "r") as archive:
                for source_member, relative_target in item["members"].items():
                    extracted = archive.extract(source_member, path=archive_path.parent)
                    target = _ensure_parent(relative_target)
                    if target.exists():
                        if target.is_dir():
                            shutil.rmtree(target)
                        else:
                            target.unlink()
                    shutil.move(extracted, target)
                    if target.is_file():
                        _mark_executable(target)
        finally:
            shutil.rmtree(archive_path.parent, ignore_errors=True)

    return actions


def render_setup_report(json_output: bool) -> str:
    state = inspect_setup_state()
    if json_output:
        return json.dumps(state, indent=2, sort_keys=True)

    lines = ["ODTS setup report", "Fetchable resources:"]
    for item in state["fetchable_resources"]:
        status = "present" if item["exists"] else "missing"
        lines.append(f"  {item['name']}: {status} -> {item['path']}")
    lines.append("Manual resources:")
    for item in state["manual_resources"]:
        status = "present" if item["exists"] else "missing"
        lines.append(f"  {item['name']}: {status} -> {item['path']}")
        lines.append(f"    reason: {item['reason']}")
    return "\n".join(lines)
