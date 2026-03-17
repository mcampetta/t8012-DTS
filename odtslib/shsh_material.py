from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from .config import PROJECT_ROOT, SHSH_PATH
from .device_state import collect_device_state_report
from .exceptions import ODTSError
from .firmware_pipeline import build_artifact_plan, load_manifest_for_planning
from .remote_ipsw import fetch_remote_firmware_metadata, select_remote_firmware
from .tool_wrappers import ToolRegistry


def _repo_aligned_build_context(product: str) -> dict[str, str] | None:
    manifest_path = PROJECT_ROOT / "resources/ipwndfu8012/BuildManifest.plist"
    if not manifest_path.exists():
        return None
    manifest = load_manifest_for_planning(manifest_path)
    if product not in set(manifest.supported_product_types):
        return None
    return {
        "build": manifest.product_build_version,
        "version": manifest.product_version,
        "source": "repo-aligned default manifest",
        "manifest_path": str(manifest_path),
    }


def _selected_build_context(product: str, build_override: str | None) -> dict[str, str]:
    if build_override:
        metadata = fetch_remote_firmware_metadata(product)
        selection = select_remote_firmware(metadata, build=build_override)
        return {
            "build": selection.build,
            "version": selection.version,
            "source": "explicit --build override",
            "manifest_path": None,
        }

    repo_context = _repo_aligned_build_context(product)
    if repo_context:
        return repo_context

    metadata = fetch_remote_firmware_metadata(product)
    selection = select_remote_firmware(metadata, build=None)
    return {
        "build": selection.build,
        "version": selection.version,
        "source": "inferred from connected device context",
        "manifest_path": None,
    }


def _latest_signed_build_context(product: str) -> dict[str, str]:
    metadata = fetch_remote_firmware_metadata(product)
    selection = select_remote_firmware(metadata, build=None)
    return {
        "build": selection.build,
        "version": selection.version,
        "source": "latest signed build for connected device context",
        "manifest_path": None,
    }


def _build_context(product: str, *, build_override: str | None, latest_signed: bool) -> dict[str, str]:
    if build_override:
        return _selected_build_context(product, build_override)
    if latest_signed:
        return _latest_signed_build_context(product)
    return _selected_build_context(product, None)


def _host_side_compatibility_probe(*, shsh_path: Path, board_config: str) -> dict[str, object]:
    manifest_path = PROJECT_ROOT / "resources/ipwndfu8012/BuildManifest.plist"
    manifest = load_manifest_for_planning(manifest_path)
    plan = build_artifact_plan(manifest, board_config)
    tools = ToolRegistry()
    temp_dir = Path(tempfile.mkdtemp(prefix="odts-sign-compat-"))
    try:
        im4m_path = temp_dir / "IM4M"
        im4m_detail = None
        im4m_generation_succeeded = False
        try:
            tools.img4tool.extract_im4m(shsh_path=shsh_path, output_path=im4m_path)
            im4m_generation_succeeded = im4m_path.exists()
        except ODTSError as exc:
            im4m_detail = str(exc)

        artifact_results = []
        for component in plan.components:
            source_path = PROJECT_ROOT / "IPSW" / component.source_path
            if not source_path.exists():
                artifact_results.append(
                    {
                        "logical_name": component.logical_name,
                        "source_path": str(source_path),
                        "attempted": False,
                        "status": "missing_source",
                        "detail": "source payload not present locally",
                    }
                )
                continue
            output_path = temp_dir / f"{component.logical_name}.img4"
            try:
                tools.img4tool.sign_img4(output_path=output_path, payload_path=source_path, shsh_path=shsh_path)
                artifact_results.append(
                    {
                        "logical_name": component.logical_name,
                        "source_path": str(source_path),
                        "attempted": True,
                        "status": "wrapped",
                        "detail": None,
                    }
                )
            except ODTSError as exc:
                artifact_results.append(
                    {
                        "logical_name": component.logical_name,
                        "source_path": str(source_path),
                        "attempted": True,
                        "status": "rejected",
                        "detail": str(exc),
                    }
                )

        attempted = [artifact for artifact in artifact_results if artifact["attempted"]]
        rejected = [artifact for artifact in attempted if artifact["status"] == "rejected"]
        wrapped = [artifact for artifact in attempted if artifact["status"] == "wrapped"]
        return {
            "manifest_path": str(manifest_path),
            "manifest_build": manifest.product_build_version,
            "manifest_version": manifest.product_version,
            "board_config": board_config,
            "im4m_generation_succeeded": im4m_generation_succeeded,
            "im4m_detail": im4m_detail,
            "artifacts": artifact_results,
            "available_artifacts_attempted": len(attempted),
            "available_artifacts_wrapped_successfully": len(wrapped),
            "available_artifacts_rejected": len(rejected),
            "host_side_mismatch_rejected": bool(rejected) or (len(attempted) > 0 and not im4m_generation_succeeded),
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def acquire_shsh_for_connected_device(*, build: str | None = None, latest_signed: bool = False) -> dict[str, object]:
    device_report = collect_device_state_report()
    product = str(device_report.identifiers.get("PRODUCT") or "")
    model = str(device_report.identifiers.get("MODEL") or "")
    ecid = str(device_report.identifiers.get("ECID") or "")

    if device_report.state != "identifiers_ready" or not product or not model or not ecid:
        raise ODTSError("SHSH acquisition requires a connected device with ECID, PRODUCT, and MODEL available.")

    build_context = _build_context(product, build_override=build, latest_signed=latest_signed)
    tools = ToolRegistry()
    tsschecker = tools.tsschecker.inspect()
    if not tsschecker.runnable or not tsschecker.path:
        raise ODTSError(f"tsschecker is not runnable: {tsschecker.detail}")

    output_path = SHSH_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    existing_bytes = output_path.read_bytes() if output_path.exists() else None

    temp_dir = Path(tempfile.mkdtemp(prefix="odts-shsh-"))
    try:
        manifest_path = build_context.get("manifest_path")
        save_path = temp_dir / "saved"
        save_path.mkdir(parents=True, exist_ok=True)
        command_preview = tools.tsschecker.build_request_shsh_command(
            device_model=product,
            ecid=ecid,
            ios_version=build_context["version"],
            board_config=model,
            build_id=build_context["build"],
            build_manifest=manifest_path,
            save_path=save_path,
            update_install=False,
        )
        try:
            result = tools.tsschecker.request_shsh(
                device_model=product,
                ecid=ecid,
                ios_version=build_context["version"],
                board_config=model,
                build_id=build_context["build"],
                build_manifest=manifest_path,
                save_path=save_path,
                update_install=False,
                cwd=temp_dir,
                dry_run=False,
            )
            candidates = sorted(save_path.glob("*.shsh2"))
            if not candidates:
                raise ODTSError(
                    "tsschecker completed without producing a .shsh2 ticket in the save-path directory."
                )
            generated = candidates[0]
            generated_bytes = generated.read_bytes()
        except ODTSError as exc:
            return {
                "device_detected": True,
                "device_state": device_report.state,
                "product": product,
                "board_config": model,
                "ecid": ecid,
                "selected_build": build_context["build"],
                "selected_version": build_context["version"],
                "build_source": build_context["source"],
                "manifest_path": manifest_path,
                "manifest_supplied_explicitly": bool(manifest_path),
                "tool": {
                    "name": "tsschecker",
                    "path": tsschecker.path,
                    "selected_candidate": tsschecker.selected_candidate,
                },
                "requested_latest_signed": latest_signed,
                "working_directory": str(temp_dir),
                "command": command_preview,
                "temp_files": sorted(str(path) for path in temp_dir.iterdir()),
                "acquired": False,
                "output_path": str(output_path),
                "write_status": "not_written",
                "failure_detail": str(exc),
                "next_recommended_command": "./venv/bin/python odts.py --acquire-shsh --json",
            }

        if output_path.exists() and existing_bytes == generated_bytes:
            write_status = "reused_existing"
        else:
            write_status = "replaced_existing" if output_path.exists() else "newly_created"
            output_path.write_bytes(generated_bytes)

        host_compatibility = _host_side_compatibility_probe(shsh_path=output_path, board_config=model)

        return {
            "device_detected": True,
            "device_state": device_report.state,
            "product": product,
            "board_config": model,
            "ecid": ecid,
            "selected_build": build_context["build"],
            "selected_version": build_context["version"],
            "build_source": build_context["source"],
            "manifest_path": manifest_path,
            "manifest_supplied_explicitly": bool(manifest_path),
            "tool": {
                "name": "tsschecker",
                "path": tsschecker.path,
                "selected_candidate": tsschecker.selected_candidate,
            },
            "requested_latest_signed": latest_signed,
            "working_directory": str(temp_dir),
            "command": command_preview,
            "temp_files": sorted(str(path) for path in temp_dir.iterdir()),
            "acquired": True,
            "output_path": str(output_path),
            "write_status": write_status,
            "generated_ticket_path": str(generated),
            "host_compatibility": host_compatibility,
            "command_result": {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            "next_recommended_command": "./venv/bin/python odts.py --preflight",
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def render_shsh_acquisition(report: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(report, indent=2, sort_keys=True)

    lines = [
        "Acquire SHSH",
        f"Device detected: {report['device_detected']}",
        f"Device state: {report['device_state']}",
        f"Product: {report['product']}",
        f"Board config: {report['board_config']}",
        f"ECID: {report['ecid']}",
        f"Selected build: {report['selected_build']}",
        f"Selected version: {report['selected_version']}",
        f"Build source: {report['build_source']}",
        f"Manifest supplied explicitly: {report['manifest_supplied_explicitly']}",
        f"Manifest path: {report['manifest_path'] or 'none'}",
        f"Source tool: {report['tool']['name']} ({report['tool']['path']})",
        f"Command: {report['command']}",
        f"Working directory: {report['working_directory']}",
        f"Signing material acquired: {report['acquired']}",
        f"Output file: {report['output_path']}",
        f"Write status: {report['write_status']}",
    ]
    if report.get("failure_detail"):
        lines.append(f"Failure detail: {report['failure_detail']}")
    if report.get("temp_files"):
        lines.append("Temp files:")
        for path in report["temp_files"]:
            lines.append(f"  - {path}")
    compatibility = report.get("host_compatibility")
    if compatibility:
        lines.append("Host-only compatibility probe:")
        lines.append(f"  - manifest_build={compatibility['manifest_build']}")
        lines.append(f"  - im4m_generation_succeeded={compatibility['im4m_generation_succeeded']}")
        if compatibility.get("im4m_detail"):
            lines.append(f"  - im4m_detail={compatibility['im4m_detail']}")
        lines.append(
            f"  - available_artifacts_wrapped_successfully={compatibility['available_artifacts_wrapped_successfully']}"
        )
        lines.append(f"  - available_artifacts_rejected={compatibility['available_artifacts_rejected']}")
        lines.append(f"  - host_side_mismatch_rejected={compatibility['host_side_mismatch_rejected']}")
    lines.append(f"Next recommended command: {report['next_recommended_command']}")
    return "\n".join(lines)
