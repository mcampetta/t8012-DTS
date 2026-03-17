from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from .config import PROJECT_ROOT
from .legacy_pwn_runtime import (
    LIBUSBFINDER_INIT,
    inspect_legacy_python_contract,
    inspect_libusb_packaging,
)
from .subprocess_utils import format_command

LOGGER = logging.getLogger(__name__)

IPWNDFU_ROOT = PROJECT_ROOT / "resources/ipwndfu8012"
PWN_MODULE = PROJECT_ROOT / "resources/pwn.py"
IPWNDFU_ENTRY = IPWNDFU_ROOT / "ipwndfu"
NOP_IMAGE4_ENTRY = IPWNDFU_ROOT / "nop_image4.py"

IMPORT_RE = re.compile(r"^\s*import\s+(.+)$", re.MULTILINE)
FROM_RE = re.compile(r"^\s*from\s+([A-Za-z0-9_\.]+)\s+import\s+(.+)$", re.MULTILINE)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _shebang(path: Path) -> str | None:
    line = _read_text(path).splitlines()[:1]
    if line and line[0].startswith("#!"):
        return line[0]
    return None


def _python2_markers(path: Path) -> list[str]:
    text = _read_text(path)
    markers: list[str] = []
    if re.search(r"^\s*print\s+['\"]", text, re.MULTILINE):
        markers.append("python2_print_statement")
    if re.search(r"\blong\b", text):
        markers.append("python2_long_type")
    if re.search(r"\bcStringIO\b", text):
        markers.append("python2_cstringio")
    if re.search(r"\.decode\('hex'\)", text):
        markers.append("python2_hex_decode")
    return markers


def _extract_import_tokens(path: Path) -> list[str]:
    text = _read_text(path)
    tokens: list[str] = []
    for match in IMPORT_RE.finditer(text):
        clause = match.group(1).split("#", 1)[0]
        for part in clause.split(","):
            token = part.strip().split(" as ", 1)[0].strip()
            if token:
                tokens.append(token)
    for match in FROM_RE.finditer(text):
        module = match.group(1).strip()
        imported = match.group(2).split("#", 1)[0]
        if module:
            tokens.append(module)
        for part in imported.split(","):
            token = part.strip().split(" as ", 1)[0].strip()
            if token == "*" or not token:
                continue
            tokens.append(f"{module}.{token}" if module else token)
    return tokens


def _candidate_paths(token: str) -> list[Path]:
    if token.startswith("resources.ipwndfu8012."):
        rel = token.replace("resources.ipwndfu8012.", "").replace(".", "/")
        return [IPWNDFU_ROOT / f"{rel}.py", IPWNDFU_ROOT / rel / "__init__.py"]
    if token.startswith("resources.ipwndfu."):
        rel = token.replace("resources.ipwndfu.", "").replace(".", "/")
        legacy_root = PROJECT_ROOT / "resources/ipwndfu"
        return [legacy_root / f"{rel}.py", legacy_root / rel / "__init__.py"]
    rel = token.replace(".", "/")
    return [IPWNDFU_ROOT / f"{rel}.py", IPWNDFU_ROOT / rel / "__init__.py"]


def _resolve_local_import(token: str) -> Path | None:
    for candidate in _candidate_paths(token):
        if candidate.exists():
            return candidate.resolve()
    return None


def _walk_import_graph(entry_points: list[Path]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    queue = [path.resolve() for path in entry_points]
    seen: set[Path] = set()
    modules: list[dict[str, object]] = []
    unresolved: list[dict[str, object]] = []

    while queue:
        path = queue.pop(0)
        if path in seen or not path.exists():
            continue
        seen.add(path)
        LOGGER.debug("Auditing static imports for %s", path)
        imports = _extract_import_tokens(path)
        resolved_imports: list[str] = []
        for token in imports:
            resolved = _resolve_local_import(token)
            if resolved:
                resolved_imports.append(str(resolved))
                if resolved not in seen:
                    queue.append(resolved)
            else:
                unresolved.append(
                    {
                        "source": str(path),
                        "import": token,
                        "classification": _classify_unresolved_import(token),
                    }
                )
        modules.append(
            {
                "path": str(path),
                "shebang": _shebang(path),
                "python2_markers": _python2_markers(path),
                "imports": imports,
                "resolved_local_imports": resolved_imports,
            }
        )
    return modules, unresolved


def _classify_unresolved_import(token: str) -> str:
    if token in {"usb", "usb.backend.libusb1", "usb.util", "usb.core"}:
        return "macOS runtime assumption"
    if token in {"cStringIO"}:
        return "python2_syntax_dependency"
    return "unknown"


def _cwd_assumptions() -> list[str]:
    return [
        "Subprocess helpers in resources/pwn.py set cwd to the repository root.",
        "The ipwndfu8012 scripts rely on script-directory imports such as `import dfu` and `import usbexec`.",
        "The legacy chain therefore assumes execution by path from a stable repo checkout.",
    ]


def _environment_assumptions() -> list[str]:
    return [
        f"{inspect_legacy_python_contract()['env_var']} can be used to supply an explicit legacy Python 2 interpreter.",
        "If the env override is not set, python2.7/python2 must be discoverable for the declared legacy runtime contract.",
        "PyUSB-compatible `usb` module is importable.",
        "The vendored libusbfinder/libusb flow is compatible with the current macOS release.",
        "No additional environment-variable override exists for alternate libusb packaging roots.",
    ]


def _entry_points() -> list[dict[str, object]]:
    contract = inspect_legacy_python_contract()
    selected = contract["selected_interpreter"]
    interpreter = str(selected["resolved_path"]) if selected else f"<set {contract['env_var']} or install python2>"
    return [
        {
            "name": "exploit_launcher",
            "path": str(IPWNDFU_ENTRY),
            "command": format_command([interpreter, IPWNDFU_ENTRY, "-p"]),
            "cwd": str(PROJECT_ROOT),
            "shebang": _shebang(IPWNDFU_ENTRY),
        },
        {
            "name": "signature_bypass_helper",
            "path": str(NOP_IMAGE4_ENTRY),
            "command": format_command([interpreter, NOP_IMAGE4_ENTRY]),
            "cwd": str(PROJECT_ROOT),
            "shebang": _shebang(NOP_IMAGE4_ENTRY),
        },
    ]


def _python2_syntax_dependencies(modules: list[dict[str, object]], unresolved: list[dict[str, object]]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for module in modules:
        markers = module["python2_markers"]
        if markers:
            findings.append(
                {
                    "classification": "python2_syntax_dependency",
                    "subject": module["path"],
                    "detail": f"Python 2-only constructs detected: {', '.join(markers)}",
                }
            )
    for item in unresolved:
        if item["classification"] == "python2_syntax_dependency":
            findings.append(
                {
                    "classification": "python2_syntax_dependency",
                    "subject": item["source"],
                    "detail": f"Import `{item['import']}` is an unresolved runtime assumption.",
                }
            )
    return findings


def _blockers(
    modules: list[dict[str, object]],
    unresolved: list[dict[str, object]],
    *,
    python_contract: dict[str, object],
    libusb_packaging: dict[str, object],
) -> list[dict[str, object]]:
    blockers: list[dict[str, object]] = []
    if not python_contract["selected_interpreter"]:
        blockers.append(
            {
                "classification": "interpreter_missing",
                "subject": str(IPWNDFU_ENTRY),
                "detail": (
                    "No explicit legacy Python 2 interpreter is available. "
                    f"Set {python_contract['env_var']} or install python2.7/python2."
                ),
            }
        )
    if not libusb_packaging["packaging_ready"]:
        blockers.append(
            {
                "classification": "external_dependency_packaging_issue",
                "subject": str(LIBUSBFINDER_INIT),
                "detail": libusb_packaging["issue"],
            }
        )
    for item in unresolved:
        if item["classification"] in {"path_assumption", "macOS runtime assumption"}:
            blockers.append(
                {
                    "classification": item["classification"],
                    "subject": item["source"],
                    "detail": f"Import `{item['import']}` is an unresolved runtime assumption.",
                }
            )
    deduped: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for blocker in blockers:
        key = (blocker["classification"], blocker["subject"], blocker["detail"])
        if key not in seen:
            seen.add(key)
            deduped.append(blocker)
    return deduped


def build_enter_pwned_dfu_runtime_audit() -> dict[str, object]:
    LOGGER.info("Building static runtime audit for enter-pwned-dfu")
    entry_paths = [IPWNDFU_ENTRY, NOP_IMAGE4_ENTRY]
    modules, unresolved = _walk_import_graph(entry_paths)
    python_contract = inspect_legacy_python_contract()
    libusb_packaging = inspect_libusb_packaging()
    syntax_dependencies = _python2_syntax_dependencies(modules, unresolved)
    runtime_boundary_preview_clean = bool(python_contract["runtime_ready"]) and bool(libusb_packaging["packaging_ready"])
    report = {
        "step": "enter-pwned-dfu",
        "module": str(PWN_MODULE),
        "entry_points": _entry_points(),
        "imported_python_files": modules,
        "unresolved_imports": unresolved,
        "interpreter_contract": python_contract,
        "libusb_packaging": libusb_packaging,
        "python2_syntax_dependencies": syntax_dependencies,
        "runtime_boundary_preview_clean": runtime_boundary_preview_clean,
        "runtime_boundary_reason": (
            "Explicit legacy Python 2 interpreter is available and libusb packaging assumptions are satisfied."
            if runtime_boundary_preview_clean
            else "Legacy interpreter contract or libusb packaging assumptions are still unresolved."
        ),
        "external_binary_tool_assumptions": [
            "ipwndfu and nop_image4.py should both execute through the same explicit legacy Python 2 interpreter.",
            "The chain depends on PyUSB/libusb rather than modern first-party wrappers.",
        ],
        "cwd_assumptions": _cwd_assumptions(),
        "environment_assumptions": _environment_assumptions(),
        "blockers": _blockers(
            modules,
            unresolved,
            python_contract=python_contract,
            libusb_packaging=libusb_packaging,
        ),
    }
    return report


def render_enter_pwned_dfu_runtime_audit(report: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(report, indent=2, sort_keys=True)

    lines = [
        "Enter pwned DFU runtime audit",
        f"Step: {report['step']}",
        f"Module: {report['module']}",
        f"Preview-Clean Runtime Boundary: {report['runtime_boundary_preview_clean']}",
        f"Runtime Boundary Reason: {report['runtime_boundary_reason']}",
        "Entry points:",
    ]
    for entry in report["entry_points"]:
        lines.append(f"  - {entry['name']}: {entry['command']}")
        lines.append(f"    cwd={entry['cwd']}")
        lines.append(f"    shebang={entry['shebang'] or 'none'}")
    lines.append("Interpreter contract:")
    contract = report["interpreter_contract"]
    lines.append(f"  - env_var={contract['env_var']}")
    selected = contract["selected_interpreter"]
    lines.append(f"  - selected_interpreter={selected['resolved_path'] if selected else 'none'}")
    lines.append(f"  - runtime_ready={contract['runtime_ready']}")
    lines.append(f"  - supported_on_modern_macos={contract['supported_on_modern_macos']}")
    lines.append("Dependency packaging:")
    packaging = report["libusb_packaging"]
    lines.append(f"  - host_macos_version={packaging['host_macos_version']}")
    lines.append(f"  - host_supported_by_vendored_libusbfinder={packaging['host_supported_by_vendored_libusbfinder']}")
    lines.append(f"  - pyusb_available={packaging['pyusb_available']}")
    lines.append(f"  - pyusb_libusb_backend_available={packaging['pyusb_libusb_backend_available']}")
    lines.append(f"  - packaging_ready={packaging['packaging_ready']}")
    if packaging.get("issue"):
        lines.append(f"  - issue={packaging['issue']}")
    lines.append("Imported Python files:")
    for module in report["imported_python_files"]:
        lines.append(
            f"  - {module['path']}: shebang={module['shebang'] or 'none'} python2_markers={module['python2_markers'] or ['none']}"
        )
    lines.append("Python 2 syntax dependencies:")
    for finding in report["python2_syntax_dependencies"]:
        lines.append(f"  - subject={finding['subject']} detail={finding['detail']}")
    if report["unresolved_imports"]:
        lines.append("Unresolved imports:")
        for item in report["unresolved_imports"]:
            lines.append(
                f"  - source={item['source']} import={item['import']} classification={item['classification']}"
            )
    lines.append("Blockers:")
    for blocker in report["blockers"]:
        lines.append(
            f"  - classification={blocker['classification']} subject={blocker['subject']} detail={blocker['detail']}"
        )
    lines.append("CWD assumptions:")
    for item in report["cwd_assumptions"]:
        lines.append(f"  - {item}")
    lines.append("Environment assumptions:")
    for item in report["environment_assumptions"]:
        lines.append(f"  - {item}")
    return "\n".join(lines)
