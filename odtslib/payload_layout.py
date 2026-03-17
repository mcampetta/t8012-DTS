from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import asdict
from pathlib import Path
from zipfile import ZipFile, is_zipfile

from .config import LOCAL_IPSW_DIR
from .exceptions import ODTSError
from .firmware_manifest import FirmwareManifest
from .firmware_pipeline import build_artifact_plan, load_manifest_for_planning


def _manifest_from_ipsw_archive(ipsw_path: Path) -> FirmwareManifest:
    if not ipsw_path.exists():
        raise ODTSError(f"Local IPSW path does not exist: {ipsw_path}")
    if not is_zipfile(ipsw_path):
        raise ODTSError(f"{ipsw_path} is not a valid IPSW zip archive.")
    with ZipFile(ipsw_path, "r") as archive:
        try:
            manifest_bytes = archive.read("BuildManifest.plist")
        except KeyError as exc:
            raise ODTSError(f"{ipsw_path} does not contain BuildManifest.plist") from exc
    temp_dir = Path(tempfile.mkdtemp(prefix="odts-manifest-"))
    manifest_path = temp_dir / "BuildManifest.plist"
    manifest_path.write_bytes(manifest_bytes)
    try:
        return load_manifest_for_planning(manifest_path)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def inspect_payload_layout(
    *,
    ipsw_path: str | Path | None,
    manifest_path: str | Path | None,
    board_config: str,
    destination_root: str | Path = LOCAL_IPSW_DIR,
    extract: bool = False,
) -> dict[str, object]:
    destination = Path(destination_root).expanduser().resolve()
    archive_path = Path(ipsw_path).expanduser().resolve() if ipsw_path else None

    if archive_path:
        manifest = _manifest_from_ipsw_archive(archive_path)
    elif manifest_path:
        manifest = load_manifest_for_planning(Path(manifest_path).expanduser().resolve())
    else:
        raise ODTSError("Payload layout inspection requires either a local IPSW archive or a manifest path.")

    plan = build_artifact_plan(manifest, board_config)
    components = []
    actions = []
    names: set[str] = set()
    archive = ZipFile(archive_path, "r") if archive_path else None
    try:
        if archive:
            names = set(archive.namelist())
        for component in plan.components:
            relative_path = component.source_path
            archive_present = relative_path in names if archive else False
            destination_path = destination / relative_path
            destination_present = destination_path.exists()
            parent_layout = str(Path(relative_path).parent)
            action = "provide file"
            if archive_path and archive_present and not destination_present:
                action = "extract IPSW"
            elif archive_path and archive_present and destination_present:
                action = "already extracted"

            component_report = {
                "logical_name": component.logical_name,
                "manifest_key": component.manifest_key,
                "relative_file": relative_path,
                "parent_layout": parent_layout,
                "source_type": "IPSW extraction",
                "archive_present": archive_present,
                "destination_path": str(destination_path),
                "destination_present": destination_present,
                "action": action,
            }
            components.append(component_report)

            if extract and archive and archive_present and not destination_present:
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(relative_path) as src, destination_path.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                actions.append({"component": component.logical_name, "extracted_to": str(destination_path)})
    finally:
        if archive:
            archive.close()

    result = {
        "board_config": board_config,
        "manifest": str(manifest.path),
        "destination_root": str(destination),
        "archive_path": str(archive_path) if archive_path else None,
        "components": components,
        "actions": actions,
        "all_components_available": all(
            component["destination_present"] or component["archive_present"] for component in components
        ),
    }
    return result


def render_payload_layout(report: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(report, indent=2, sort_keys=True)

    lines = [
        "Payload layout",
        f"Board: {report['board_config']}",
        f"Destination root: {report['destination_root']}",
        f"Archive: {report['archive_path'] or 'none'}",
        f"All planned payloads available from archive or destination: {report['all_components_available']}",
        "Components:",
    ]
    for component in report["components"]:
        lines.append(
            f"  - {component['logical_name']}: relative_file={component['relative_file']} action={component['action']}"
        )
        lines.append(f"    parent_layout={component['parent_layout']}")
        lines.append(f"    source_type={component['source_type']}")
        lines.append(f"    archive_present={component['archive_present']}")
        lines.append(f"    destination_present={component['destination_present']}")
        lines.append(f"    destination_path={component['destination_path']}")
    if report["actions"]:
        lines.append("Extraction actions:")
        for action in report["actions"]:
            lines.append(f"  - {action['component']}: extracted_to={action['extracted_to']}")
    return "\n".join(lines)
