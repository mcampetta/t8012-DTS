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
    parser.add_argument("-q", "--ipsw", nargs=2, metavar=("PATH", "DEVICE"), help="Use a local IPSW PATH for DEVICE")
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
    parser.add_argument("--validate-firmware", action="store_true", help="Inspect a manifest or local IPSW and report the planned firmware artifact flow")
    parser.add_argument("--manifest", help="Path to a BuildManifest.plist for non-destructive firmware validation")
    parser.add_argument("--board-config", help="Explicit board config for firmware validation, for example j132ap")
    parser.add_argument("--dry-run", action="store_true", help="Plan actions without executing device or filesystem mutations")
    parser.add_argument("--json", action="store_true", help="Emit diagnostic output as JSON")
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
        print(f"  {tool['name']}: exists={tool['exists']} runnable={tool['runnable']} version={tool['version']}")
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


def run_local_ipsw_flow(args: argparse.Namespace, logger) -> int:
    from resources import img4, pwn

    tools = ToolRegistry()
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
    logger = configure_logging(args.log_level, args.log_file)

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
