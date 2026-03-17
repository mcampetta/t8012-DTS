from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path

from .config import PROJECT_ROOT
from .subprocess_utils import format_command, run_command

LOGGER = logging.getLogger(__name__)

PWN_MODULE = PROJECT_ROOT / "resources/pwn.py"
IPWNDFU_8012 = PROJECT_ROOT / "resources/ipwndfu8012/ipwndfu"
NOP_IMAGE4 = PROJECT_ROOT / "resources/ipwndfu8012/nop_image4.py"
IPWNDFU_8012_DFU = PROJECT_ROOT / "resources/ipwndfu8012/dfu.py"
IPWNDFU_8012_USBEXEC = PROJECT_ROOT / "resources/ipwndfu8012/usbexec.py"
IPWNDFU_8012_CHECKM8 = PROJECT_ROOT / "resources/ipwndfu8012/checkm8.py"
IPWNDFU_8012_HEAP_FIX = PROJECT_ROOT / "resources/ipwndfu8012/t8012_heap_fix.py"


def _file_status(path: Path, *, role: str) -> dict[str, object]:
    LOGGER.debug("Checking dependency path %s", path)
    return {
        "path": str(path),
        "role": role,
        "exists": path.exists(),
        "is_file": path.is_file(),
        "executable": path.is_file() and path.stat().st_mode & 0o111 != 0,
    }


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _shebang(path: Path) -> str | None:
    first_line = _read_text(path).splitlines()[:1]
    if not first_line:
        return None
    return first_line[0] if first_line[0].startswith("#!") else None


def _python2_markers(path: Path) -> list[str]:
    text = _read_text(path)
    markers: list[str] = []
    if re.search(r"^\s*print\s+'", text, re.MULTILINE):
        markers.append("python2_print_statement")
    if re.search(r"\blong\b", text):
        markers.append("python2_long_type")
    return markers


def _command_probe(path: Path, *args: str) -> dict[str, object]:
    command = [path, *args]
    LOGGER.debug("Safely probing launcher command %s", format_command(command))
    shebang = _shebang(path)
    if shebang:
        interpreter = shebang[2:].strip().split()[0]
        if interpreter.startswith("/") and not Path(interpreter).exists():
            return {
                "command": format_command(command),
                "safe_to_probe": True,
                "runnable": False,
                "status": "missing_interpreter",
                "returncode": None,
                "stdout": "",
                "stderr": f"script shebang requires missing interpreter {interpreter}",
            }
    try:
        result = run_command(command, cwd=PROJECT_ROOT, check=False)
    except Exception as exc:  # pragma: no cover - exercised via concrete assertions
        return {
            "command": format_command(command),
            "safe_to_probe": True,
            "runnable": False,
            "status": "probe_failed",
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
        }
    return {
        "command": format_command(command),
        "safe_to_probe": True,
        "runnable": result.returncode == 0 or "USAGE:" in (result.stdout + result.stderr),
        "status": "ok" if result.returncode == 0 or "USAGE:" in (result.stdout + result.stderr) else "bad_exit_code",
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _interpreter_status(name: str) -> dict[str, object]:
    resolved = shutil.which(name)
    LOGGER.debug("Checking interpreter %s -> %s", name, resolved)
    return {
        "name": name,
        "resolved_path": resolved,
        "present": bool(resolved),
    }


def build_enter_pwned_dfu_preview() -> dict[str, object]:
    LOGGER.info("Building non-destructive enter-pwned-dfu preview")
    ipwndfu_command = [str(IPWNDFU_8012), "-p"]
    nop_image4_command = ["python", str(NOP_IMAGE4)]

    file_dependencies = [
        _file_status(PWN_MODULE, role="legacy orchestrator"),
        _file_status(IPWNDFU_8012, role="primary exploit launcher"),
        _file_status(NOP_IMAGE4, role="post-pwn signature bypass helper"),
        _file_status(IPWNDFU_8012_DFU, role="USB DFU helper imported by nop_image4"),
        _file_status(IPWNDFU_8012_USBEXEC, role="USB exec helper imported by nop_image4"),
        _file_status(IPWNDFU_8012_CHECKM8, role="checkm8 implementation imported by ipwndfu"),
        _file_status(IPWNDFU_8012_HEAP_FIX, role="T8012 heap fix imported by ipwndfu"),
    ]

    ipwndfu_probe = _command_probe(IPWNDFU_8012)
    python_status = _interpreter_status("python")
    python2_status = _interpreter_status("python2")
    python27_status = _interpreter_status("python2.7")

    ipwndfu_markers = _python2_markers(IPWNDFU_8012)
    dfu_markers = _python2_markers(IPWNDFU_8012_DFU)
    usbexec_markers = _python2_markers(IPWNDFU_8012_USBEXEC)

    analysis = {
        "step": "enter-pwned-dfu",
        "classification": "unverified",
        "module": "resources/pwn.py",
        "helper": "resources/ipwndfu8012/nop_image4.py",
        "board_scope": "T8012 / CPID:8012 path used by current T2 lab target",
        "cwd": str(PROJECT_ROOT),
        "call_graph": [
            "odts.py:run_pwn_only or local/remote live flow",
            "resources.pwn.pwndfumode()",
            "resources/ipwndfu8012/ipwndfu -p",
            "re-acquire DFU device and inspect serial for PWND:[checkm8]",
            "python resources/ipwndfu8012/nop_image4.py",
        ],
        "commands": [
            {
                "name": "exploit_launcher",
                "command": format_command(ipwndfu_command),
                "cwd": str(PROJECT_ROOT),
                "safe_to_probe": True,
                "probe": ipwndfu_probe,
            },
            {
                "name": "signature_bypass_helper",
                "command": format_command(nop_image4_command),
                "cwd": str(PROJECT_ROOT),
                "safe_to_probe": False,
                "probe": {
                    "runnable": False,
                    "status": "unsafe_to_probe",
                    "reason": "script immediately imports USB/DFU helpers and would attempt device access",
                },
            },
        ],
        "interpreter_assumptions": [
            {
                "target": str(IPWNDFU_8012),
                "shebang": _shebang(IPWNDFU_8012),
                "python2_markers": ipwndfu_markers,
                "requires_python2_runtime": bool(ipwndfu_markers),
                "interpreter_candidates": [python2_status, python27_status],
            },
            {
                "target": str(NOP_IMAGE4),
                "invoked_as": "python resources/ipwndfu8012/nop_image4.py",
                "python_launcher": python_status,
                "transitive_python2_markers": {
                    str(IPWNDFU_8012_DFU): dfu_markers,
                    str(IPWNDFU_8012_USBEXEC): usbexec_markers,
                },
                "effective_runtime_requires_python2": bool(dfu_markers or usbexec_markers),
            },
        ],
        "files": file_dependencies,
        "environment_assumptions": [
            "Current working directory is the repository root.",
            "The ipwndfu8012 launcher relies on executing a Python 2 script via its shebang.",
            "The nop_image4 helper is invoked through bare `python` from resources/pwn.py.",
            "Sibling-module imports are expected to resolve from resources/ipwndfu8012.",
            "PyUSB/libusb access must be available to the legacy DFU helpers at runtime.",
        ],
        "expected_pre_state": [
            "Device is connected in DFU-capable pre-exploit state.",
            "Device serial contains CPID:8012.",
            "Device serial does not already contain PWND:[checkm8].",
        ],
        "expected_post_state": [
            "After ipwndfu -p, device serial is expected to include PWND:[checkm8].",
            "After nop_image4.py, image_load is patched out for subsequent raw image handling.",
            "nop_image4.py performs DFU abort and USB reset before returning.",
        ],
        "stdout_stderr_patterns": {
            "exploit_success": [
                "Device is now in pwned DFU Mode.",
                "Exploit worked! patching out signature checks",
            ],
            "exploit_failure": [
                "ERROR: Exploit failed. Device did not enter pwned DFU Mode.",
                "ERROR: No Apple device",
                "Exploit failed, reboot device into DFU mode and press enter to re-run checkm8",
            ],
            "helper_success": [
                "Removed image_load call; all incoming images will be loaded as raw",
            ],
            "modern_macos_failures": [
                "bad interpreter: /usr/bin/python: no such file or directory",
                "command not found: python",
                "SyntaxError",
                "No module named usb",
                "No module named libusbfinder",
            ],
        },
        "likely_failure_points_on_modern_macos": [
            "resources/ipwndfu8012/ipwndfu requires /usr/bin/python, which is absent on modern macOS installs.",
            "resources/pwn.py invokes nop_image4.py via bare `python`, but no `python` launcher exists on this host.",
            "nop_image4.py imports local helpers with Python 2 syntax, so a Python 3 fallback would still fail.",
            "Legacy DFU helpers depend on PyUSB/libusb availability outside the modern wrapper layer.",
            "The legacy path reacquires the device after a sleep and assumes stable USB re-enumeration timing.",
        ],
        "stop_conditions_for_future_controlled_test": [
            "Do not proceed if the launcher interpreter contract is unresolved.",
            "Do not proceed if preview reports missing dependency files.",
            "Do not proceed if safe launcher probing fails with bad interpreter or missing module errors.",
            "Stop immediately on any unexpected USB disconnect or mode transition in a future live test.",
        ],
    }
    return analysis


def render_enter_pwned_dfu_preview(report: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(report, indent=2, sort_keys=True)

    lines = [
        "Enter pwned DFU preview",
        f"Step: {report['step']}",
        f"Classification: {report['classification']}",
        f"Module: {report['module']}",
        f"Helper: {report['helper']}",
        f"CWD: {report['cwd']}",
        "Call graph:",
    ]
    for entry in report["call_graph"]:
        lines.append(f"  - {entry}")
    lines.append("Commands:")
    for command in report["commands"]:
        lines.append(f"  - {command['name']}: {command['command']}")
        lines.append(f"    cwd={command['cwd']}")
        lines.append(f"    safe_to_probe={command['safe_to_probe']}")
        probe = command["probe"]
        lines.append(f"    probe_status={probe['status']}")
        if "reason" in probe:
            lines.append(f"    reason={probe['reason']}")
        if "stderr" in probe and probe["stderr"]:
            lines.append(f"    stderr={str(probe['stderr']).splitlines()[0][:200]}")
    lines.append("Interpreter assumptions:")
    for entry in report["interpreter_assumptions"]:
        lines.append(f"  - target={entry['target']}")
        if "shebang" in entry:
            lines.append(f"    shebang={entry['shebang']}")
        if "invoked_as" in entry:
            lines.append(f"    invoked_as={entry['invoked_as']}")
        if "requires_python2_runtime" in entry:
            lines.append(f"    requires_python2_runtime={entry['requires_python2_runtime']}")
        if "effective_runtime_requires_python2" in entry:
            lines.append(f"    effective_runtime_requires_python2={entry['effective_runtime_requires_python2']}")
    lines.append("Files:")
    for file_report in report["files"]:
        lines.append(
            f"  - {file_report['path']}: exists={file_report['exists']} executable={file_report['executable']} role={file_report['role']}"
        )
    lines.append("Likely failure points on modern macOS:")
    for item in report["likely_failure_points_on_modern_macos"]:
        lines.append(f"  - {item}")
    return "\n".join(lines)
