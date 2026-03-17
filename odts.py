#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import platform
import shutil
import sys
from pathlib import Path

from odtslib.cleanup import remove_staged_files
from odtslib.config import (
    DEVICE_MAP_PATH,
    LOCAL_IPSW_DIR,
    PROJECT_ROOT,
    SHSH_PATH,
    TOOL_VERSION,
)
from odtslib.device import is_a10_a11_or_t2, parse_irecovery_query, read_board_config
from odtslib.device_state import collect_device_state_report, inspect_device_state
from odtslib.execution_preflight import (
    build_execution_graph,
    build_execution_preflight,
    render_execution_graph,
    render_execution_preflight,
)
from odtslib.legacy_pwn_runtime import build_legacy_pwn_runtime_check, render_legacy_pwn_runtime_check
from odtslib.payload_layout import inspect_payload_layout, render_payload_layout
from odtslib.pwn_preview import build_enter_pwned_dfu_preview, render_enter_pwned_dfu_preview
from odtslib.pwn_runtime_audit import (
    build_enter_pwned_dfu_runtime_audit,
    render_enter_pwned_dfu_runtime_audit,
)
from odtslib.remote_ipsw import inspect_remote_payload_layout, render_remote_payload_layout
from odtslib.shsh_material import acquire_shsh_for_connected_device, render_shsh_acquisition
from odtslib.diagnostics import collect_diagnostics
from odtslib.exceptions import DependencyError, DeviceStateError, ODTSError, UnsupportedHostError
from odtslib.firmware_pipeline import (
    build_artifact_plan,
    generate_stage_results,
    load_manifest_for_planning,
    render_plan_report,
)
from odtslib.logging_utils import configure_logging
from odtslib.setup import fetch_missing_resources, render_setup_report
from odtslib.tool_wrappers import ToolRegistry

from resources import ipsw

DESCRIPTION = (
    "Ontrack Data Transfer Setup (ODTS) prepares ramdisk boot assets for T2 devices. "
    "This modernized wrapper preserves the legacy workflows where possible while adding "
    "diagnostics, dry-run support, and explicit failure reporting."
)

CREDITS = [
    "Martin (@hotshotmc) - original ODTS implementation",
    "Matty (@mosk_i) - PyBoot work referenced by the original tool",
    "axi0mX - ipwndfu/checkm8",
    "thimstar - img4tool, tsschecker, iBoot64Patcher",
    "Linus Henze - Fugu",
    "Merculous - ios-python-tools",
    "0x7ff - Eclipsa",
    "libimobiledevice team - irecovery",
    "Ralph0045 - dtree_patcher / Kernel64Patcher",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("command", nargs="?", choices=["setup"], help="Optional management command")
    parser.add_argument("-i", "--ios", nargs=2, metavar=("DEVICE", "IOS"), help="Download assets for DEVICE and IOS")
    parser.add_argument(
        "-q",
        "--ipsw",
        nargs="+",
        metavar=("PATH", "DEVICE"),
        help="Use a local IPSW PATH for DEVICE. With --prepare-device, --payload-layout, or --validate-firmware, PATH alone is accepted.",
    )
    parser.add_argument("-b", "--bootlogo", metavar="LOGO", help="Path to a custom PNG boot logo")
    parser.add_argument("-p", "--pwn", action="store_true", help="Enter pwned DFU mode")
    parser.add_argument("--amfi", action="store_true", help="Apply AMFI kernel patches when supported")
    parser.add_argument("--debug", action="store_true", help="Enable serial debug boot arguments when dual booting")
    parser.add_argument("-d", "--dualboot", metavar="PARTITION", help="Boot an alternate system partition")
    parser.add_argument("-a", "--bootargs", metavar="BOOTARGS", help="Explicit boot arguments to pass through")
    parser.add_argument("-v", "--version", action="store_true", help="Show the tool version")
    parser.add_argument("-c", "--credits", action="store_true", help="Show credits")
    parser.add_argument("-f", "--fix", action="store_true", help="Deprecated legacy repair flow")
    parser.add_argument("--diagnostic", action="store_true", help="Collect a non-destructive environment report")
    parser.add_argument("--device-state", action="store_true", help="Inspect connected device state without modifying it")
    parser.add_argument("--validate-firmware", action="store_true", help="Inspect a manifest or local IPSW and report the planned firmware artifact flow")
    parser.add_argument("--execution-graph", action="store_true", help="Render the non-destructive planned execution graph for the selected or connected device")
    parser.add_argument("--preflight", action="store_true", help="Run a non-destructive execution preflight for the selected or connected device")
    parser.add_argument("--payload-layout", action="store_true", help="Inspect or prepare the expected local payload layout for the planned components")
    parser.add_argument("--remote-payload-layout", metavar="DEVICE", help="Inspect or prepare planned payloads directly from a remote restore IPSW without full local download")
    parser.add_argument("--prepare-device", action="store_true", help="Detect a connected device, prepare planned payloads into IPSW/, and run non-destructive preflight")
    parser.add_argument("--preview-enter-pwned-dfu", action="store_true", help="Preview the first execution-side step with file, interpreter, and launcher diagnostics only")
    parser.add_argument("--audit-enter-pwned-dfu-runtime", action="store_true", help="Statically audit the full legacy runtime compatibility chain for enter-pwned-dfu without execution")
    parser.add_argument("--check-legacy-pwn-runtime", action="store_true", help="Check the host-side legacy T8012 Python/libusb runtime contract without execution")
    parser.add_argument("--acquire-shsh", action="store_true", help="Safely acquire signing material for the connected device and selected build into resources/shsh.shsh")
    parser.add_argument("--latest-signed", action="store_true", help="With --acquire-shsh, target the currently signed build for the connected device instead of the repo-aligned default build")
    parser.add_argument("--extract-planned-payloads", action="store_true", help="With --payload-layout or --remote-payload-layout, extract only the planned payload files into a safe local directory")
    parser.add_argument("--payload-root", help="Optional destination root for planned payload layout inspection or extraction")
    parser.add_argument("--build", help="Optional build override for remote payload layout lookup, for example 19P647")
    parser.add_argument("--manifest", help="Path to a BuildManifest.plist for non-destructive firmware validation")
    parser.add_argument("--board-config", help="Explicit board config for firmware validation, for example j132ap")
    parser.add_argument("--dry-run", action="store_true", help="Plan actions without executing device or filesystem mutations")
    parser.add_argument("--json", action="store_true", help="Emit diagnostic output as JSON")
    parser.add_argument("--verbose", action="store_true", help="Emit more detailed operator-facing output for inspection commands")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--log-file", help="Optional path to a log file")
    parser.add_argument("--fetch-missing", action="store_true", help="With `setup`, download supported missing repo-local resources")
    return parser


def print_credits() -> None:
    for credit in CREDITS:
        print(credit)


def determine_boot_args(args: argparse.Namespace) -> str:
    if args.dualboot:
        if args.bootargs:
            return args.bootargs
        if args.debug:
            return f"-v serial=3 rd={args.dualboot}"
        return f"-v rd={args.dualboot}"
    return args.bootargs or "rd=md0 -v"


def require_supported_host(*, dry_run: bool) -> None:
    if platform.system() == "Darwin":
        return
    if dry_run:
        return
    raise UnsupportedHostError(
        f"ODTS execution requires macOS. Current host is {platform.system()}."
    )


def find_generated_shsh() -> Path:
    for candidate in PROJECT_ROOT.glob("*.shsh2"):
        return candidate
    raise ODTSError("tsschecker completed without producing a .shsh2 ticket in the repository root.")


def sign_iboot_images(board_config: str, dry_run: bool) -> None:
    tools = ToolRegistry()
    tools.img4tool.sign_img4(
        output_path=PROJECT_ROOT / "resources/StagedFiles/ibss.img4",
        payload_path=PROJECT_ROOT / f"resources/Firmware/Firmware/dfu/iBSS.{board_config}.RELEASE.im4p",
        shsh_path=SHSH_PATH,
        image_type="ibss",
        dry_run=dry_run,
    )
    tools.img4tool.sign_img4(
        output_path=PROJECT_ROOT / "resources/StagedFiles/ibec.img4",
        payload_path=PROJECT_ROOT / f"resources/Firmware/Firmware/dfu/iBEC.{board_config}.RELEASE.im4p",
        shsh_path=SHSH_PATH,
        image_type="ibec",
        dry_run=dry_run,
    )


def run_diagnostics(json_output: bool) -> int:
    report = collect_diagnostics()
    if json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print("ODTS diagnostic report")
    print(f"Project root: {report['project_root']}")
    host = report["host"]
    print(f"Host: {host['platform']} {host['platform_release']} | Python {host['python']}")
    print(f"Runtime supported on this host: {host['host_supported']}")
    print("Dependency status:")
    for name, status in report["dependencies"].items():
        print(f"  {name}: {status}")
    print("Resource checks:")
    for entry in report["resources"]:
        state = "present" if entry["exists"] else "missing"
        print(f"  {entry['path']}: {state}")
    print("Legacy Python 2 components:")
    for path in report["legacy_python2_components"]:
        print(f"  {path}")
    print("External tools:")
    for tool in report["external_tools"]:
        print(
            f"  {tool['name']}: exists={tool['exists']} runnable={tool['runnable']} "
            f"path={tool['path']} selected={tool.get('selected_candidate')} version={tool['version']}"
        )
        for candidate in tool.get("candidates", []):
            selected = " selected" if candidate.get("selected") else ""
            print(
                f"    - {candidate['label']}{selected}: status={candidate['status']} "
                f"path={candidate.get('path')} detail={candidate['detail']}"
            )
    return 0


def run_firmware_validation(args: argparse.Namespace, logger) -> int:
    manifest_path: Path
    if args.manifest:
        manifest_path = Path(args.manifest).expanduser().resolve()
        if not manifest_path.exists():
            raise ODTSError(f"Manifest path does not exist: {manifest_path}")
    elif args.ipsw:
        ipsw_path = Path(args.ipsw[0]).expanduser().resolve()
        if not ipsw_path.exists():
            raise ODTSError(f"Local IPSW path does not exist: {ipsw_path}")
        logger.info("Extracting local IPSW for non-destructive validation from %s", ipsw_path)
        ipsw.unzip_ipsw(ipsw_path)
        manifest_path = LOCAL_IPSW_DIR / "BuildManifest.plist"
    else:
        raise ODTSError("Firmware validation requires either `--manifest PATH` or `-q PATH DEVICE`.")

    manifest = load_manifest_for_planning(manifest_path)
    board_config = args.board_config
    if not board_config:
        if args.ipsw and len(manifest.build_identities) == 1:
            board_config = manifest.build_identities[0].device_class
        else:
            raise ODTSError(
                "Firmware validation requires `--board-config` unless the manifest contains exactly one build identity."
            )

    plan = build_artifact_plan(manifest, board_config)
    report = {
        "manifest": str(manifest_path),
        "board_config": board_config,
        "stages": [asdict(stage) for stage in generate_stage_results(manifest, board_config)],
        "artifact_plan": render_plan_report(plan),
    }
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else json.dumps(report, indent=2))
    return 0


def _resolve_manifest_path_for_safe_planning(args: argparse.Namespace, logger) -> Path:
    if args.manifest:
        manifest_path = Path(args.manifest).expanduser().resolve()
        if not manifest_path.exists():
            raise ODTSError(f"Manifest path does not exist: {manifest_path}")
        return manifest_path
    if args.ipsw:
        ipsw_path = Path(args.ipsw[0]).expanduser().resolve()
        if not ipsw_path.exists():
            raise ODTSError(f"Local IPSW path does not exist: {ipsw_path}")
        logger.info("Extracting local IPSW for non-destructive planning from %s", ipsw_path)
        ipsw.unzip_ipsw(ipsw_path)
        return LOCAL_IPSW_DIR / "BuildManifest.plist"
    bundled_manifest = PROJECT_ROOT / "resources/ipwndfu8012/BuildManifest.plist"
    if bundled_manifest.exists():
        return bundled_manifest
    raise ODTSError("No manifest source available. Use --manifest PATH or -q PATH DEVICE.")


def _default_repo_build() -> str | None:
    bundled_manifest = PROJECT_ROOT / "resources/ipwndfu8012/BuildManifest.plist"
    if not bundled_manifest.exists():
        return None
    try:
        return load_manifest_for_planning(bundled_manifest).product_build_version
    except ODTSError:
        return None


def _render_prepare_device(report: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(report, indent=2, sort_keys=True)

    lines = [
        "Prepare device",
        f"Device detected: {report['device_detected']}",
        f"Device state: {report['device_state']}",
        f"Product: {report['product'] or 'unknown'}",
        f"Board config: {report['board_config'] or 'unknown'}",
        f"Payload build: {report['selected_build'] or 'unknown'}",
        f"Build source: {report['build_source'] or 'unknown'}",
        f"Payload source used: {report['payload_source_used']}",
    ]
    if report.get("payload_source_detail"):
        lines.append(f"Payload source detail: {report['payload_source_detail']}")
    if report.get("payload_extraction_result"):
        lines.append(f"Extraction result: {report['payload_extraction_result']}")
    if report.get("preflight_result"):
        lines.append(f"Preflight result: {report['preflight_result']}")
    if report.get("readiness_level"):
        lines.append(f"Current readiness level: {report['readiness_level']}")
    if report.get("shsh_build_used"):
        lines.append(f"SHSH build used: {report['shsh_build_used']}")
    if report.get("shsh_fallback_used") is not None:
        lines.append(f"SHSH fallback to latest signed used: {report['shsh_fallback_used']}")
    if report.get("host_side_artifact_compatibility_succeeded") is not None:
        lines.append(
            "Host-side artifact compatibility succeeded: "
            f"{report['host_side_artifact_compatibility_succeeded']}"
        )
    if report.get("next_recommended_command"):
        lines.append(f"Next recommended command: {report['next_recommended_command']}")
    if report.get("notes"):
        lines.append("Notes:")
        for note in report["notes"]:
            lines.append(f"  - {note}")
    return "\n".join(lines)


def run_prepare_device(args: argparse.Namespace, logger) -> int:
    logger.info("Preparing connected device for payload sourcing and non-destructive preflight")
    device_report = collect_device_state_report()
    product = str(device_report.identifiers.get("PRODUCT") or "")
    board_config = str(device_report.identifiers.get("MODEL") or "")
    repo_default_build = _default_repo_build()
    initial_build = args.build or repo_default_build
    initial_build_source = (
        "explicit --build override"
        if args.build
        else "repo-aligned default manifest"
        if repo_default_build
        else "inferred from connected device context"
    )
    report: dict[str, object] = {
        "device_detected": device_report.state == "identifiers_ready",
        "device_state": device_report.state,
        "product": product or None,
        "board_config": board_config or None,
        "selected_build": initial_build,
        "build_source": initial_build_source,
        "payload_source_used": "none",
        "payload_source_detail": None,
        "payload_extraction_result": None,
        "preflight_result": None,
        "readiness_level": None,
        "shsh_build_used": None,
        "shsh_fallback_used": None,
        "host_side_artifact_compatibility_succeeded": None,
        "next_recommended_command": None,
        "device_report": asdict(device_report),
        "payload_report": None,
        "preflight": None,
        "notes": [],
    }

    if device_report.state != "identifiers_ready" or not product or not board_config:
        report["notes"].append("Connected device identifiers are not ready for planning.")
        report["next_recommended_command"] = "./venv/bin/python odts.py --device-state --verbose"
        print(_render_prepare_device(report, json_output=args.json))
        return 2

    if args.ipsw:
        ipsw_path = Path(args.ipsw[0]).expanduser().resolve()
        if not ipsw_path.exists():
            raise ODTSError(f"Local IPSW path does not exist: {ipsw_path}")
        payload_report = inspect_payload_layout(
            ipsw_path=ipsw_path,
            manifest_path=None,
            board_config=board_config,
            destination_root=args.payload_root or LOCAL_IPSW_DIR,
            extract=True,
        )
        manifest_path = Path(payload_report["manifest_destination"] or LOCAL_IPSW_DIR / "BuildManifest.plist")
        report["selected_build"] = payload_report.get("build") or report["selected_build"]
        report["build_source"] = "local IPSW manifest" if not args.build else "explicit --build override"
        report["payload_source_used"] = "local_ipsw"
        report["payload_source_detail"] = str(ipsw_path)
        report["payload_extraction_result"] = (
            f"{len(payload_report['actions'])} extraction/reuse action(s); "
            f"all_components_available={payload_report['all_components_available']}"
        )
    else:
        selected_build = initial_build
        payload_report = inspect_remote_payload_layout(
            device=product,
            board_config=board_config,
            build=selected_build,
            destination_root=args.payload_root or LOCAL_IPSW_DIR,
            extract=True,
        )
        report["selected_build"] = payload_report.get("build") or selected_build
        report["payload_source_used"] = "remote_ipsw"
        report["payload_source_detail"] = payload_report.get("remote_url")
        if payload_report.get("fallback"):
            report["payload_extraction_result"] = "remote payload inspection failed"
            report["payload_report"] = payload_report
            report["notes"].append(payload_report["fallback"]["reason"])
            report["next_recommended_command"] = payload_report["fallback"]["next_step"]
            print(_render_prepare_device(report, json_output=args.json))
            return 2
        manifest_path = Path(payload_report["manifest_destination"])
        report["payload_extraction_result"] = (
            f"{len(payload_report['actions'])} extraction/reuse action(s); "
            f"all_planned_payloads_available_remotely={payload_report['all_planned_payloads_available_remotely']}"
        )

    manifest = load_manifest_for_planning(manifest_path)
    preflight = build_execution_preflight(manifest, board_config)
    report["payload_report"] = payload_report
    report["preflight"] = preflight
    report["preflight_result"] = "no blockers" if not preflight["blockers"] else f"{len(preflight['blockers'])} blocker(s)"
    report["readiness_level"] = preflight["readiness"]["level"]
    report["shsh_build_used"] = preflight["readiness"].get("shsh_build_used")
    report["shsh_fallback_used"] = preflight["readiness"].get("shsh_fallback_used")
    report["host_side_artifact_compatibility_succeeded"] = preflight["readiness"].get(
        "host_side_artifact_compatibility_succeeded"
    )
    if any("signing material missing" in blocker for blocker in preflight["blockers"]):
        report["next_recommended_command"] = "./venv/bin/python odts.py --acquire-shsh"
    elif not preflight["blockers"]:
        report["next_recommended_command"] = "./venv/bin/python odts.py --preview-enter-pwned-dfu"
    else:
        report["next_recommended_command"] = "./venv/bin/python odts.py --preflight"
    print(_render_prepare_device(report, json_output=args.json))
    return 0


def run_execution_graph(args: argparse.Namespace, logger) -> int:
    manifest_path = _resolve_manifest_path_for_safe_planning(args, logger)
    manifest = load_manifest_for_planning(manifest_path)
    graph = build_execution_graph(manifest, args.board_config)
    print(render_execution_graph(graph, json_output=args.json))
    return 0


def run_execution_preflight(args: argparse.Namespace, logger) -> int:
    manifest_path = _resolve_manifest_path_for_safe_planning(args, logger)
    manifest = load_manifest_for_planning(manifest_path)
    preflight = build_execution_preflight(manifest, args.board_config)
    print(render_execution_preflight(preflight, json_output=args.json))
    return 0


def run_payload_layout(args: argparse.Namespace, logger) -> int:
    manifest_path = None if args.ipsw else _resolve_manifest_path_for_safe_planning(args, logger)
    board_config = args.board_config
    if not board_config:
        device_report = collect_device_state_report()
        board_config = str(device_report.identifiers.get("MODEL") or "")
        if not board_config:
            raise ODTSError("Payload layout inspection requires --board-config or a connected device with a detected MODEL.")
    report = inspect_payload_layout(
        ipsw_path=args.ipsw[0] if args.ipsw else None,
        manifest_path=manifest_path,
        board_config=board_config,
        destination_root=args.payload_root or LOCAL_IPSW_DIR,
        extract=args.extract_planned_payloads,
    )
    print(render_payload_layout(report, json_output=args.json))
    return 0


def run_remote_payload_layout(args: argparse.Namespace, logger) -> int:
    board_config = args.board_config
    if not board_config:
        device_report = collect_device_state_report()
        board_config = str(device_report.identifiers.get("MODEL") or "")
        if not board_config:
            raise ODTSError(
                "Remote payload layout inspection requires --board-config or a connected device with a detected MODEL."
            )
    selected_build = args.build
    if not selected_build:
        try:
            manifest_path = _resolve_manifest_path_for_safe_planning(args, logger)
            manifest = load_manifest_for_planning(manifest_path)
            selected_build = manifest.product_build_version
        except ODTSError:
            selected_build = None
    logger.info(
        "Inspecting remote payload layout for device=%s board=%s build=%s",
        args.remote_payload_layout,
        board_config,
        selected_build or "latest signed",
    )
    report = inspect_remote_payload_layout(
        device=args.remote_payload_layout,
        board_config=board_config,
        build=selected_build,
        destination_root=args.payload_root or LOCAL_IPSW_DIR,
        extract=args.extract_planned_payloads,
    )
    print(render_remote_payload_layout(report, json_output=args.json))
    return 0


def run_preview_enter_pwned_dfu(args: argparse.Namespace, logger) -> int:
    logger.info("Previewing enter-pwned-dfu without hardware interaction")
    report = build_enter_pwned_dfu_preview()
    print(render_enter_pwned_dfu_preview(report, json_output=args.json))
    return 0


def run_audit_enter_pwned_dfu_runtime(args: argparse.Namespace, logger) -> int:
    logger.info("Auditing enter-pwned-dfu runtime compatibility without execution")
    report = build_enter_pwned_dfu_runtime_audit()
    print(render_enter_pwned_dfu_runtime_audit(report, json_output=args.json))
    return 0


def run_check_legacy_pwn_runtime(args: argparse.Namespace, logger) -> int:
    logger.info("Checking legacy pwn runtime contract without execution")
    report = build_legacy_pwn_runtime_check()
    print(render_legacy_pwn_runtime_check(report, json_output=args.json))
    return 0


def run_acquire_shsh(args: argparse.Namespace, logger) -> int:
    logger.info("Acquiring SHSH signing material without exploit or live execution")
    report = acquire_shsh_for_connected_device(build=args.build, latest_signed=args.latest_signed)
    print(render_shsh_acquisition(report, json_output=args.json))
    return 0 if report.get("acquired") else 2


def run_local_ipsw_flow(args: argparse.Namespace, logger) -> int:
    from resources import img4, pwn

    tools = ToolRegistry()
    if len(args.ipsw) != 2:
        raise ODTSError("Legacy local IPSW mode requires `-q PATH DEVICE`.")
    ipsw_path = Path(args.ipsw[0]).expanduser().resolve()
    device_model = args.ipsw[1]
    if not ipsw_path.exists():
        raise ODTSError(f"Local IPSW path does not exist: {ipsw_path}")

    logger.info("Preparing local IPSW workflow for %s from %s", device_model, ipsw_path)
    ios_version = ipsw.unzip_ipsw(ipsw_path)
    supported_models = ipsw.read_manifest(LOCAL_IPSW_DIR / "BuildManifest.plist", return_version=False)
    if device_model not in supported_models:
        raise ODTSError(f"Selected IPSW does not list {device_model} in SupportedProductTypes.")

    use_custom_logo = bool(args.bootlogo)
    boot_args = determine_boot_args(args)
    logger.info("Local IPSW identified as iBridge/iOS %s", ios_version)

    if args.dry_run:
        logger.info("Dry-run: would stage IMG4 artifacts, exploit the device, and send boot images.")
        return 0

    irecovery_query = tools.irecovery.query(dry_run=False)
    parsed = parse_irecovery_query(irecovery_query.stdout)
    bdid = parsed.get("BDID")
    if not bdid:
        raise DeviceStateError("Unable to read BDID from irecovery output for local IPSW mode.")
    board_config = read_board_config(bdid.replace("0x", "").replace("0X", "")[:2].upper(), DEVICE_MAP_PATH)

    img4.img4stuff(
        device_model,
        ios_version,
        use_custom_logo,
        args.bootlogo or "null",
        True,
        bool(args.dualboot),
        boot_args,
        args.amfi,
        board_config,
    )
    pwn.pwndfumode()
    img4.sendImages(ios_version, use_custom_logo, is_a10_a11_or_t2(device_model))
    return 0


def run_remote_flow(args: argparse.Namespace, logger) -> int:
    from resources import img4

    tools = ToolRegistry()
    device_model, ios_version = args.ios
    boot_args = determine_boot_args(args)
    use_custom_logo = bool(args.bootlogo)
    logger.info("Preparing remote IPSW workflow for %s on iOS %s", device_model, ios_version)

    irecovery_query = tools.irecovery.query(dry_run=args.dry_run)
    parsed = parse_irecovery_query(irecovery_query.stdout)
    ecid = parsed.get("ECID")
    bdid = parsed.get("BDID")
    if not ecid or not bdid:
        raise DeviceStateError("Unable to read ECID/BDID from irecovery output.")

    short_bdid = bdid.replace("0x", "").replace("0X", "")[:2].upper()
    board_config = read_board_config(short_bdid)
    logger.info("Connected device ECID=%s BDID=%s board=%s", ecid, bdid, board_config)

    if args.dry_run:
        logger.info("Dry-run: would request SHSH, stage assets, and send boot images.")
        return 0

    tools.tsschecker.request_shsh(device_model=device_model, ecid=ecid, ios_version=ios_version, dry_run=False)
    generated_ticket = find_generated_shsh()
    shutil.move(str(generated_ticket), SHSH_PATH)

    img4.img4stuff(
        device_model,
        ios_version,
        use_custom_logo,
        args.bootlogo or "null",
        False,
        bool(args.dualboot),
        boot_args,
        args.amfi,
        board_config,
    )
    sign_iboot_images(board_config, dry_run=False)
    img4.sendImages(ios_version, use_custom_logo, is_a10_a11_or_t2(device_model))
    return 0


def run_pwn_only(args: argparse.Namespace, logger) -> int:
    from resources import pwn

    if args.dry_run:
        logger.info("Dry-run: would enter pwned DFU mode using the bundled legacy tooling.")
        return 0
    pwn.pwndfumode()
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    effective_log_level = args.log_level
    if args.json and effective_log_level.upper() == "INFO":
        effective_log_level = "ERROR"
    logger = configure_logging(effective_log_level, args.log_file)

    try:
        if args.version:
            print(f"ODTS version {TOOL_VERSION}")
            return 0
        if args.command == "setup":
            print(render_setup_report(args.json))
            if args.fetch_missing:
                actions = fetch_missing_resources(dry_run=args.dry_run)
                if args.json:
                    print(json.dumps({"actions": actions}, indent=2, sort_keys=True))
                elif actions:
                    for action in actions:
                        logger.info(
                            "%s %s from %s",
                            "Would fetch" if args.dry_run else "Fetched",
                            action["path"],
                            action["url"],
                        )
                else:
                    logger.info("No supported repo-local resources are missing.")
                return 0
            return 0
        if args.credits:
            print_credits()
            return 0
        if args.device_state:
            print(inspect_device_state(json_output=args.json, verbose=args.verbose))
            return 0
        if args.preview_enter_pwned_dfu:
            return run_preview_enter_pwned_dfu(args, logger)
        if args.audit_enter_pwned_dfu_runtime:
            return run_audit_enter_pwned_dfu_runtime(args, logger)
        if args.check_legacy_pwn_runtime:
            return run_check_legacy_pwn_runtime(args, logger)
        if args.acquire_shsh:
            return run_acquire_shsh(args, logger)
        if args.prepare_device:
            return run_prepare_device(args, logger)
        if args.remote_payload_layout:
            return run_remote_payload_layout(args, logger)
        if args.payload_layout:
            return run_payload_layout(args, logger)
        if args.execution_graph:
            return run_execution_graph(args, logger)
        if args.preflight:
            return run_execution_preflight(args, logger)
        if args.validate_firmware:
            return run_firmware_validation(args, logger)
        if args.diagnostic and not any([args.ios, args.ipsw, args.pwn]):
            return run_diagnostics(args.json)
        if args.fix:
            raise ODTSError(
                "The legacy `--fix` workflow was removed because it downloaded and installed tooling at runtime, "
                "modified /usr/local, and attempted host-level package installation. See RUNBOOK.md for manual repair steps."
            )

        require_supported_host(dry_run=args.dry_run)
        removed = remove_staged_files()
        if removed:
            logger.debug("Removed %d staged artifact(s)", len(removed))

        if args.ipsw:
            return run_local_ipsw_flow(args, logger)
        if args.ios:
            return run_remote_flow(args, logger)
        if args.pwn:
            return run_pwn_only(args, logger)
        if args.diagnostic:
            return run_diagnostics(args.json)

        parser.print_help(sys.stderr)
        return 1
    except (ODTSError, DependencyError, DeviceStateError, UnsupportedHostError) as exc:
        logger.error(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
