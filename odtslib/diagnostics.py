from __future__ import annotations

import importlib
import json
import platform
import shutil
import sys
from pathlib import Path

from .config import EXPECTED_RUNTIME_FILES, LEGACY_PYTHON2_PATHS, PROJECT_ROOT, SUPPORTED_HOST
from .tool_wrappers import ToolRegistry


def _module_state(name: str) -> dict[str, str]:
    try:
        module = importlib.import_module(name)
    except Exception as exc:  # pragma: no cover - diagnostic path
        return {"status": "missing", "detail": str(exc)}
    version = getattr(module, "__version__", "unknown")
    return {"status": "ok", "detail": str(version)}


def collect_diagnostics() -> dict[str, object]:
    tools = ToolRegistry()
    files = []
    for relative_path in EXPECTED_RUNTIME_FILES:
        path = PROJECT_ROOT / relative_path
        files.append(
            {
                "path": relative_path,
                "exists": path.exists(),
                "size": path.stat().st_size if path.exists() and path.is_file() else None,
            }
        )

    return {
        "project_root": str(PROJECT_ROOT),
        "host": {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "python": sys.version.split()[0],
            "supported_runtime_host": SUPPORTED_HOST,
            "host_supported": platform.system() == SUPPORTED_HOST,
        },
        "dependencies": {
            "requests": _module_state("requests"),
            "remotezip": _module_state("remotezip"),
            "usb": _module_state("usb"),
            "bs4": _module_state("bs4"),
            "irecovery_on_path": shutil.which("irecovery"),
        },
        "resources": files,
        "legacy_python2_components": LEGACY_PYTHON2_PATHS,
        "repo_hygiene": {
            "venv_in_repo": (PROJECT_ROOT / "venv").exists(),
            "ds_store_in_repo": (PROJECT_ROOT / ".DS_Store").exists(),
            "pycache_dirs": sorted(str(path.relative_to(PROJECT_ROOT)) for path in PROJECT_ROOT.rglob("__pycache__")),
        },
        "external_tools": tools.inspect(dry_run=platform.system() != SUPPORTED_HOST),
    }


def render_diagnostics_json() -> str:
    return json.dumps(collect_diagnostics(), indent=2, sort_keys=True)
