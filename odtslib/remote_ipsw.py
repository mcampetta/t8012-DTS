from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from remotezip import RemoteZip, RemoteZipError

from .config import LOCAL_IPSW_DIR
from .exceptions import ODTSError
from .firmware_manifest import FirmwareManifest
from .firmware_pipeline import build_artifact_plan, load_manifest_for_planning

IPSW_API_TEMPLATE = "https://api.ipsw.me/v4/device/{device}?type=ipsw"
REMOTE_CACHE_NAME = ".odts-remote-payload-cache.json"


@dataclass(frozen=True)
class RemoteFirmwareSelection:
    device: str
    version: str
    build: str
    url: str
    signed: bool


def fetch_remote_firmware_metadata(device: str, *, session: requests.Session | None = None) -> dict[str, Any]:
    client = session or requests.Session()
    response = client.get(IPSW_API_TEMPLATE.format(device=device), timeout=30)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or "firmwares" not in payload:
        raise ODTSError(f"Unexpected metadata response for {device}")
    return payload


def select_remote_firmware(
    metadata: dict[str, Any],
    *,
    build: str | None = None,
) -> RemoteFirmwareSelection:
    device = str(metadata.get("identifier") or metadata.get("name") or "")
    firmwares = metadata.get("firmwares") or []
    if not firmwares:
        raise ODTSError("No firmware entries were returned by the metadata source.")

    if build:
        for entry in firmwares:
            if str(entry.get("buildid")) == build:
                return RemoteFirmwareSelection(
                    device=device,
                    version=str(entry.get("version")),
                    build=str(entry.get("buildid")),
                    url=str(entry.get("url")),
                    signed=bool(entry.get("signed")),
                )
        raise ODTSError(f"Requested build {build} was not found for {device}.")

    for entry in firmwares:
        if entry.get("signed") and entry.get("url"):
            return RemoteFirmwareSelection(
                device=device,
                version=str(entry.get("version")),
                build=str(entry.get("buildid")),
                url=str(entry.get("url")),
                signed=bool(entry.get("signed")),
            )

    first = firmwares[0]
    return RemoteFirmwareSelection(
        device=device,
        version=str(first.get("version")),
        build=str(first.get("buildid")),
        url=str(first.get("url")),
        signed=bool(first.get("signed")),
    )


def _manifest_from_remote_zip(url: str, *, session: requests.Session | None = None) -> tuple[FirmwareManifest, list[str]]:
    client = session or requests.Session()
    temp_dir = Path(tempfile.mkdtemp(prefix="odts-remote-manifest-"))
    manifest_path = temp_dir / "BuildManifest.plist"
    archive = None
    try:
        archive = RemoteZip(url, session=client)
        names = archive.namelist()
        if "BuildManifest.plist" not in names:
            raise ODTSError("Remote archive does not contain BuildManifest.plist.")
        manifest_path.write_bytes(archive.read("BuildManifest.plist"))
        manifest = load_manifest_for_planning(manifest_path)
        return manifest, names
    except (RemoteZipError, requests.RequestException, OSError) as exc:
        raise ODTSError(f"Remote archive inspection failed: {exc}") from exc
    finally:
        if archive:
            archive.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def _cache_path(destination_root: Path) -> Path:
    return destination_root / REMOTE_CACHE_NAME


def _write_cache(destination_root: Path, payload: dict[str, object]) -> str:
    destination_root.mkdir(parents=True, exist_ok=True)
    cache_path = _cache_path(destination_root)
    cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(cache_path)


def inspect_remote_payload_layout(
    *,
    device: str,
    board_config: str,
    build: str | None = None,
    destination_root: str | Path = LOCAL_IPSW_DIR,
    extract: bool = False,
    replace_existing: bool = False,
    session: requests.Session | None = None,
) -> dict[str, object]:
    metadata = fetch_remote_firmware_metadata(device, session=session)
    selection = select_remote_firmware(metadata, build=build)
    destination = Path(destination_root).expanduser().resolve()
    metadata_source = IPSW_API_TEMPLATE.format(device=device)

    try:
        manifest, names = _manifest_from_remote_zip(selection.url, session=session)
        range_access_working = True
        fallback = None
    except ODTSError as exc:
        range_access_working = False
        fallback = {
            "classification": "remote_unavailable_use_local_ipsw",
            "reason": str(exc),
            "resolved_url": selection.url,
            "next_step": f"./venv/bin/python odts.py -q /path/to/{Path(selection.url).name} {device} --payload-layout",
        }
        return {
            "device": selection.device or device,
            "version": selection.version,
            "build": selection.build,
            "remote_url": selection.url,
            "metadata_source": metadata_source,
            "range_access_working": range_access_working,
            "remote_archive_inspection_succeeded": False,
            "fallback": fallback,
            "cache_path": None,
        }

    supported_types = set(manifest.supported_product_types)
    if device not in supported_types:
        raise ODTSError(
            f"Remote BuildManifest for {selection.build} does not list {device} in SupportedProductTypes."
        )

    plan = build_artifact_plan(manifest, board_config)
    actions = []
    archive = None
    components = []
    try:
        archive = RemoteZip(selection.url, session=session or requests.Session())
        for component in plan.components:
            relative_path = component.source_path
            remote_present = relative_path in names
            destination_path = destination / relative_path
            destination_present = destination_path.exists()

            action = "provide file"
            if remote_present and destination_present and not replace_existing:
                action = "reused_existing"
            elif remote_present and destination_present and replace_existing:
                action = "replace_existing"
            elif remote_present:
                action = "extract_remote"
            else:
                action = "missing_remote"

            if extract and remote_present:
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                if destination_present and not replace_existing:
                    pass
                else:
                    if destination_present and replace_existing:
                        destination_path.unlink()
                    with archive.open(relative_path) as src, destination_path.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    actions.append(
                        {
                            "component": component.logical_name,
                            "status": "replaced" if destination_present and replace_existing else "extracted",
                            "destination_path": str(destination_path),
                        }
                    )
                if destination_present and not replace_existing:
                    actions.append(
                        {
                            "component": component.logical_name,
                            "status": "reused",
                            "destination_path": str(destination_path),
                        }
                    )

            components.append(
                {
                    "logical_name": component.logical_name,
                    "manifest_key": component.manifest_key,
                    "relative_file": relative_path,
                    "parent_layout": str(Path(relative_path).parent),
                    "source_type": "remote IPSW extraction",
                    "remote_present": remote_present,
                    "destination_path": str(destination_path),
                    "destination_present": destination_path.exists(),
                    "action": action,
                }
            )

        manifest_destination = destination / "BuildManifest.plist"
        manifest_present = manifest_destination.exists()
        manifest_action = "reused_existing" if manifest_present and not replace_existing else "extract_remote"
        if extract:
            manifest_destination.parent.mkdir(parents=True, exist_ok=True)
            if not manifest_present or replace_existing:
                manifest_destination.write_bytes(archive.read("BuildManifest.plist"))
                actions.append(
                    {
                        "component": "BuildManifest",
                        "status": "replaced" if manifest_present and replace_existing else "extracted",
                        "destination_path": str(manifest_destination),
                    }
                )
            else:
                actions.append(
                    {
                        "component": "BuildManifest",
                        "status": "reused",
                        "destination_path": str(manifest_destination),
                    }
                )

        cache_payload = {
            "device": selection.device or device,
            "version": selection.version,
            "build": selection.build,
            "board_config": board_config,
            "remote_url": selection.url,
            "metadata_source": metadata_source,
            "range_access_working": True,
            "remote_archive_inspection_succeeded": True,
            "manifest_destination": str(manifest_destination),
            "all_planned_payloads_available_remotely": all(component["remote_present"] for component in components),
            "extracted_payloads": [
                action["component"]
                for action in actions
                if action["component"] != "BuildManifest" and action["status"] in {"extracted", "replaced", "reused"}
            ],
        }
        cache_path = _write_cache(destination, cache_payload)
        return {
            "device": selection.device or device,
            "version": selection.version,
            "build": selection.build,
            "remote_url": selection.url,
            "metadata_source": metadata_source,
            "range_access_working": True,
            "remote_archive_inspection_succeeded": True,
            "board_config": board_config,
            "manifest_destination": str(manifest_destination),
            "manifest_action": manifest_action,
            "components": components,
            "actions": actions,
            "all_planned_payloads_available_remotely": all(component["remote_present"] for component in components),
            "next_step": "./venv/bin/python odts.py --preflight",
            "fallback": None,
            "cache_path": cache_path,
        }
    except (RemoteZipError, requests.RequestException, OSError) as exc:
        return {
            "device": selection.device or device,
            "version": selection.version,
            "build": selection.build,
            "remote_url": selection.url,
            "metadata_source": metadata_source,
            "range_access_working": False,
            "remote_archive_inspection_succeeded": False,
            "fallback": {
                "classification": "remote_unavailable_use_local_ipsw",
                "reason": str(exc),
                "resolved_url": selection.url,
                "next_step": f"./venv/bin/python odts.py -q /path/to/{Path(selection.url).name} {device} --payload-layout",
            },
            "cache_path": None,
        }
    finally:
        if archive:
            archive.close()


def render_remote_payload_layout(report: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(report, indent=2, sort_keys=True)

    lines = [
        "Remote payload layout",
        f"Device: {report['device']}",
        f"Version: {report['version']}",
        f"Build: {report['build']}",
        f"Metadata source: {report['metadata_source']}",
        f"Remote restore URL: {report['remote_url']}",
        f"Range access working: {report['range_access_working']}",
        f"Remote inspection succeeded: {report['remote_archive_inspection_succeeded']}",
        f"Cache file: {report.get('cache_path') or 'none'}",
    ]
    if report.get("fallback"):
        lines.append("Fallback:")
        lines.append(f"  - classification={report['fallback']['classification']}")
        lines.append(f"  - reason={report['fallback']['reason']}")
        lines.append(f"  - resolved_url={report['fallback']['resolved_url']}")
        lines.append(f"  - next_step={report['fallback']['next_step']}")
        return "\n".join(lines)

    lines.append(f"Board: {report['board_config']}")
    lines.append(f"Manifest destination: {report['manifest_destination']} ({report['manifest_action']})")
    lines.append(
        f"All planned payloads available remotely: {report['all_planned_payloads_available_remotely']}"
    )
    lines.append("Components:")
    for component in report["components"]:
        lines.append(
            f"  - {component['logical_name']}: remote_present={component['remote_present']} "
            f"action={component['action']} destination={component['destination_path']}"
        )
        lines.append(f"    relative_file={component['relative_file']}")
        lines.append(f"    parent_layout={component['parent_layout']}")
    if report["actions"]:
        lines.append("Extraction actions:")
        for action in report["actions"]:
            lines.append(
                f"  - {action['component']}: status={action['status']} destination={action['destination_path']}"
            )
    lines.append(f"Next step: {report['next_step']}")
    return "\n".join(lines)
