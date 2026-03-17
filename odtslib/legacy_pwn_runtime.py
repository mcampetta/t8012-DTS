from __future__ import annotations

import importlib.util
import json
import os
import platform
import re
import shutil
from pathlib import Path

from .config import PROJECT_ROOT
from .exceptions import ODTSError
from .subprocess_utils import run_command

LEGACY_PYTHON_ENV = "ODTS_LEGACY_PYTHON"
LEGACY_PYTHON_CANDIDATES = ("python2.7", "python2")
LIBUSBFINDER_INIT = PROJECT_ROOT / "resources/ipwndfu8012/libusbfinder/__init__.py"
LIBUSBFINDER_BOTTLES = PROJECT_ROOT / "resources/ipwndfu8012/libusbfinder/bottles"


def _resolve_interpreter(reference: str) -> str | None:
    candidate = Path(reference).expanduser()
    if candidate.is_absolute() or "/" in reference:
        if candidate.exists() and candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
        return None
    return shutil.which(reference)


def inspect_legacy_python_contract() -> dict[str, object]:
    env_value = os.environ.get(LEGACY_PYTHON_ENV)
    candidates: list[dict[str, object]] = []
    selected: dict[str, object] | None = None

    if env_value:
        resolved = _resolve_interpreter(env_value)
        entry = {
            "reference": env_value,
            "source": "env",
            "resolved_path": resolved,
            "present": bool(resolved),
        }
        candidates.append(entry)
        if resolved:
            selected = entry

    for reference in LEGACY_PYTHON_CANDIDATES:
        resolved = _resolve_interpreter(reference)
        entry = {
            "reference": reference,
            "source": "path",
            "resolved_path": resolved,
            "present": bool(resolved),
        }
        candidates.append(entry)
        if resolved and selected is None:
            selected = entry

    return {
        "contract": "explicit_legacy_python2",
        "env_var": LEGACY_PYTHON_ENV,
        "supported_on_modern_macos": (
            "Supported only when an explicit Python 2 interpreter is provided via "
            f"{LEGACY_PYTHON_ENV} or discoverable as python2.7/python2."
        ),
        "selected_interpreter": selected,
        "candidates": candidates,
        "runtime_ready": bool(selected),
    }


def _interpreter_version(interpreter: str) -> dict[str, object]:
    try:
        result = run_command([interpreter, "--version"], check=False)
    except ODTSError as exc:
        return {"version": None, "major": None, "minor": None, "ok": False, "detail": str(exc)}
    output = (result.stderr or result.stdout).strip()
    match = re.search(r"Python\s+(\d+)\.(\d+)", output)
    if not match:
        return {"version": output or None, "major": None, "minor": None, "ok": False, "detail": "unparseable version"}
    major = int(match.group(1))
    minor = int(match.group(2))
    return {
        "version": output,
        "major": major,
        "minor": minor,
        "ok": major == 2 and minor == 7,
        "detail": None if major == 2 and minor == 7 else "interpreter is not Python 2.7",
    }


def legacy_python_script_command(script_path: str | Path, *args: str) -> list[str]:
    contract = inspect_legacy_python_contract()
    selected = contract["selected_interpreter"]
    if not selected:
        raise ODTSError(
            f"Legacy Python runtime is unavailable. Set {LEGACY_PYTHON_ENV} or install python2.7/python2."
        )
    script = Path(script_path)
    resolved_script = script if script.is_absolute() else PROJECT_ROOT / script
    return [str(selected["resolved_path"]), str(resolved_script), *args]


def _supported_libusb_versions() -> list[str]:
    text = LIBUSBFINDER_INIT.read_text(encoding="utf-8", errors="replace")
    return re.findall(r"version='([^']+)'", text)


def inspect_libusb_packaging() -> dict[str, object]:
    host_version = platform.mac_ver()[0]
    supported_versions = _supported_libusb_versions()
    mapped_host = "10.14" if host_version == "10.15" else host_version
    host_supported = any(mapped_host.startswith(version) for version in supported_versions) if mapped_host else False
    pyusb_present = bool(importlib.util.find_spec("usb"))
    backend_present = bool(importlib.util.find_spec("usb.backend.libusb1"))
    return {
        "host_macos_version": host_version or "unknown",
        "supported_versions": supported_versions,
        "vendored_bottles_present": LIBUSBFINDER_BOTTLES.exists(),
        "host_supported_by_vendored_libusbfinder": host_supported,
        "pyusb_available": pyusb_present,
        "pyusb_libusb_backend_available": backend_present,
        "packaging_ready": host_supported and pyusb_present and backend_present,
        "issue": (
            None
            if host_supported and pyusb_present and backend_present
            else "Vendored libusbfinder/libusb assumptions are not clean for the current host runtime."
        ),
    }


def _safe_import_check_current_host() -> dict[str, object]:
    modules = {}
    for name in ("usb", "usb.backend.libusb1"):
        spec = importlib.util.find_spec(name)
        modules[name] = {"ok": bool(spec), "detail": None, "origin": getattr(spec, "origin", None) if spec else None}
    return {"strategy": "current_host_python", "modules": modules}


def _safe_import_check_selected_interpreter(interpreter: str | None) -> dict[str, object]:
    if not interpreter:
        return {
            "strategy": "selected_legacy_interpreter",
            "interpreter": None,
            "checked": False,
            "modules": {},
            "detail": "no selected legacy interpreter",
        }
    script = (
        "import json\n"
        "mods=['usb','usb.backend.libusb1']\n"
        "results={}\n"
        "for mod in mods:\n"
        "    try:\n"
        "        loaded = __import__(mod, fromlist=['_odts'])\n"
        "        results[mod]={'ok': True, 'detail': None, 'origin': getattr(loaded, '__file__', None)}\n"
        "    except Exception as exc:\n"
        "        results[mod]={'ok': False, 'detail': '%s: %s' % (exc.__class__.__name__, exc), 'origin': None}\n"
        "print(json.dumps(results, sort_keys=True))\n"
    )
    try:
        result = run_command([interpreter, "-c", script], check=False)
    except ODTSError as exc:
        return {
            "strategy": "selected_legacy_interpreter",
            "interpreter": interpreter,
            "checked": False,
            "modules": {},
            "detail": str(exc),
        }
    if result.returncode != 0:
        return {
            "strategy": "selected_legacy_interpreter",
            "interpreter": interpreter,
            "checked": False,
            "modules": {},
            "detail": (result.stderr or result.stdout).strip() or "import check failed",
        }
    return {
        "strategy": "selected_legacy_interpreter",
        "interpreter": interpreter,
        "checked": True,
        "modules": json.loads(result.stdout),
        "detail": None,
    }


def _classify_import_boundary(detail: str | None) -> str | None:
    if not detail:
        return None
    lowered = detail.lower()
    if "no module named util" in lowered:
        return "relative_import_issue"
    if "no module named usb" in lowered:
        return "transitive_dependency_issue"
    if "no module named" in lowered:
        return "legacy_packaging_assumption"
    return "unknown_runtime_issue"


def build_legacy_pwn_runtime_check() -> dict[str, object]:
    contract = inspect_legacy_python_contract()
    selected = contract["selected_interpreter"]
    selected_path = str(selected["resolved_path"]) if selected else None
    selected_version = _interpreter_version(selected_path) if selected_path else {
        "version": None,
        "major": None,
        "minor": None,
        "ok": False,
        "detail": "no selected interpreter",
    }
    for candidate in contract["candidates"]:
        if candidate["resolved_path"]:
            candidate["version"] = _interpreter_version(str(candidate["resolved_path"]))
        else:
            candidate["version"] = {"version": None, "major": None, "minor": None, "ok": False, "detail": "missing"}

    host_imports = _safe_import_check_current_host()
    selected_imports = _safe_import_check_selected_interpreter(selected_path)
    libusb_packaging = inspect_libusb_packaging()

    issues: list[dict[str, object]] = []
    if not selected_path:
        issues.append(
            {
                "classification": "missing_python2",
                "detail": f"No Python 2.7 interpreter selected. Set {LEGACY_PYTHON_ENV} or install python2.7/python2.",
            }
        )
    elif not selected_version["ok"]:
        issues.append(
            {
                "classification": "wrong_python_version",
                "detail": f"Selected interpreter reports {selected_version['version']}, expected Python 2.7.",
            }
        )

    selected_modules = selected_imports["modules"]
    host_modules = host_imports["modules"]
    usb_ok = selected_modules.get("usb", {}).get("ok") if selected_imports["checked"] else False
    libusb_backend_ok = (
        selected_modules.get("usb.backend.libusb1", {}).get("ok")
        if selected_imports["checked"]
        else False
    )
    backend_detail = (
        selected_modules.get("usb.backend.libusb1", {}).get("detail")
        if selected_imports["checked"]
        else None
    )
    usb_origin = selected_modules.get("usb", {}).get("origin") if selected_imports["checked"] else None
    backend_origin = selected_modules.get("usb.backend.libusb1", {}).get("origin") if selected_imports["checked"] else None
    backend_issue_category = _classify_import_boundary(backend_detail)

    interpreter_ready = bool(selected_path and selected_version["ok"])
    module_import_ready = bool(usb_ok)
    libusb_backend_ready = bool(libusb_backend_ok)
    vendored_libusbfinder_ready = bool(
        libusb_packaging["vendored_bottles_present"] and libusb_packaging["host_supported_by_vendored_libusbfinder"]
    )

    if selected_imports["checked"] and not usb_ok:
        issues.append({"classification": "missing_pyusb", "detail": "Python module `usb` is not importable."})
    if selected_imports["checked"] and not libusb_backend_ok:
        issues.append(
            {
                "classification": "missing_libusb",
                "detail": (
                    "Python module `usb.backend.libusb1` is not importable."
                    + (f" Detail: {backend_detail}" if backend_detail else "")
                ),
            }
        )
    if not libusb_packaging["packaging_ready"]:
        issues.append(
            {
                "classification": "libusbfinder_packaging_issue",
                "detail": libusb_packaging["issue"],
            }
        )
    return {
        "contract": contract,
        "selected_interpreter_value": selected_path,
        "selected_interpreter_version": selected_version,
        "python2_7_available": any(
            candidate["reference"] == "python2.7" and bool(candidate["resolved_path"])
            for candidate in contract["candidates"]
        ),
        "interpreter_ready": interpreter_ready,
        "module_import_ready": module_import_ready,
        "libusb_backend_ready": libusb_backend_ready,
        "vendored_libusbfinder_ready": vendored_libusbfinder_ready,
        "safe_import_checks": {
            "current_host_python": host_imports,
            "selected_interpreter": selected_imports,
        },
        "import_boundary_analysis": {
            "selected_interpreter_usb_origin": usb_origin,
            "selected_interpreter_backend_origin": backend_origin,
            "selected_interpreter_backend_detail": backend_detail,
            "selected_interpreter_backend_issue_category": backend_issue_category,
        },
        "libusb_packaging": libusb_packaging,
        "issues": issues,
        "preview_clean_runtime_boundary": bool(
            interpreter_ready and module_import_ready and libusb_backend_ready and vendored_libusbfinder_ready
        ),
        "suggested_export": (
            f"export {LEGACY_PYTHON_ENV}=/absolute/path/to/python2.7"
            if not selected_path
            else f"export {LEGACY_PYTHON_ENV}={selected_path}"
        ),
    }


def render_legacy_pwn_runtime_check(report: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(report, indent=2, sort_keys=True)

    lines = [
        "Legacy pwn runtime check",
        "Summary:",
        f"  - preview_clean_runtime_boundary={report['preview_clean_runtime_boundary']}",
        f"  - interpreter_ready={report['interpreter_ready']}",
        f"  - module_import_ready={report['module_import_ready']}",
        f"  - libusb_backend_ready={report['libusb_backend_ready']}",
        f"  - vendored_libusbfinder_ready={report['vendored_libusbfinder_ready']}",
        "Interpreter contract:",
        f"  - selected_{LEGACY_PYTHON_ENV}={report['selected_interpreter_value'] or 'none'}",
        f"  - selected_interpreter_version={report['selected_interpreter_version']['version'] or 'none'}",
        f"  - python2_7_available={report['python2_7_available']}",
        "Fallback candidates:",
    ]
    for candidate in report["contract"]["candidates"]:
        lines.append(
            f"  - {candidate['reference']}: present={candidate['present']} resolved={candidate['resolved_path'] or 'none'} "
            f"version={candidate['version']['version'] or 'none'}"
        )
    lines.append("Safe import checks:")
    for name, payload in report["safe_import_checks"].items():
        lines.append(f"  - {name}: checked={payload.get('checked', True)} modules={payload['modules']}")
        if payload.get("detail"):
            lines.append(f"    detail={payload['detail']}")
    boundary = report["import_boundary_analysis"]
    if (
        boundary.get("selected_interpreter_usb_origin")
        or boundary.get("selected_interpreter_backend_origin")
        or boundary.get("selected_interpreter_backend_detail")
    ):
        lines.append("Import boundary analysis:")
        if boundary.get("selected_interpreter_usb_origin"):
            lines.append(f"  - selected_interpreter_usb_origin={boundary['selected_interpreter_usb_origin']}")
        if boundary.get("selected_interpreter_backend_origin"):
            lines.append(f"  - selected_interpreter_backend_origin={boundary['selected_interpreter_backend_origin']}")
        lines.append(f"  - selected_interpreter_backend_issue_category={boundary['selected_interpreter_backend_issue_category']}")
        lines.append(f"  - selected_interpreter_backend_detail={boundary['selected_interpreter_backend_detail']}")
    packaging = report["libusb_packaging"]
    lines.append("libusb/libusbfinder packaging:")
    lines.append(f"  - host_macos_version={packaging['host_macos_version']}")
    lines.append(f"  - host_supported_by_vendored_libusbfinder={packaging['host_supported_by_vendored_libusbfinder']}")
    lines.append(f"  - pyusb_available={packaging['pyusb_available']}")
    lines.append(f"  - pyusb_libusb_backend_available={packaging['pyusb_libusb_backend_available']}")
    lines.append(f"  - packaging_ready={packaging['packaging_ready']}")
    if packaging.get("issue"):
        lines.append(f"  - issue={packaging['issue']}")
    lines.append("Issues:")
    for issue in report["issues"]:
        lines.append(f"  - {issue['classification']}: {issue['detail']}")
    lines.append(f"Suggested export: {report['suggested_export']}")
    return "\n".join(lines)
