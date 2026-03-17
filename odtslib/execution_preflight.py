from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import LOCAL_IPSW_DIR, PROJECT_ROOT, RESOURCES_DIR, SHSH_PATH
from .device import read_board_config
from .device_state import DeviceStateName, collect_device_state_report
from .exceptions import ODTSError
from .firmware_manifest import FirmwareManifest
from .firmware_pipeline import FirmwareArtifactPlan, build_artifact_plan
from .tool_wrappers import ToolRegistry


@dataclass(frozen=True)
class ExecutionStep:
    name: str
    description: str
    tool: str | None
    module: str | None
    status: str


@dataclass(frozen=True)
class PlannedComponentStep:
    logical_name: str
    manifest_key: str
    source_path: str
    output_path: str
    source_candidates: tuple[str, ...]
    steps: tuple[ExecutionStep, ...]


@dataclass(frozen=True)
class LegacyTouchpoint:
    path: str
    role: str
    status: str
    exists: bool


@dataclass(frozen=True)
class ReadinessSummary:
    level: str
    rationale: str
    only_blocker_is_missing_payload_material: bool
    operator_action_needed: str
    would_valid_local_payloads_enable_live_step_testing: bool
    first_execution_step_name: str
    first_execution_step_classification: str
    first_execution_step_tool: str | None
    first_execution_step_module: str | None
    first_safe_live_test_candidate: str | None
    stop_conditions: tuple[str, ...]


STEP_STATUS = {
    "planning": "validated",
    "legacy": "legacy",
    "live": "unverified",
    "unverified": "unverified",
}

TOOL_ATTRS = {
    "irecovery": "irecovery",
    "img4tool": "img4tool",
    "img4": "img4",
    "ibootim": "ibootim",
    "iBoot64Patcher": "iboot64patcher",
    "Kernel64Patcher": "kernel64patcher",
    "dtree_patcher": "dtree_patcher",
    "kairos": "kairos",
}

LEGACY_TOUCHPOINTS = (
    ("resources/img4.py", "execution pipeline / patch-sign-send orchestration", "legacy"),
    ("resources/pwn.py", "pwned DFU / exploit orchestration", "legacy"),
    ("resources/ipwndfu8012/ipwndfu", "legacy exploit helper", "unverified"),
    ("resources/ipwndfu8012/nop_image4.py", "signature bypass helper", "unverified"),
)

SOURCE_KIND = {
    "ibec": "local IPSW extraction",
    "ibss": "local IPSW extraction",
    "kernelcache": "local IPSW extraction",
    "devicetree": "local IPSW extraction",
    "trustcache": "local IPSW extraction",
    "aopfw": "local IPSW extraction",
    "touch": "local IPSW extraction",
}

EXPECTATION_MODULE = {
    "ibec": "resources/img4.py",
    "ibss": "resources/img4.py",
    "kernelcache": "resources/img4.py",
    "devicetree": "resources/img4.py",
    "trustcache": "resources/img4.py",
    "aopfw": "resources/img4.py",
    "touch": "resources/img4.py",
}


def _derive_source_path(logical_name: str, source_path: str) -> str:
    if logical_name == "kernelcache":
        return "BuildManifest component path is already a top-level IPSW payload path."
    return "BuildManifest component path is treated as a relative path under the extracted IPSW root."


def _root_cause_category(logical_name: str, source_candidates: tuple[str, ...]) -> str:
    canonical_candidate = Path(source_candidates[0]) if source_candidates else None
    if canonical_candidate and not canonical_candidate.exists():
        return "missing local files"
    if any("/resources/Firmware/Firmware/" in candidate for candidate in source_candidates):
        return "stale legacy assumptions"
    return "path mismatch"


def _proposed_fix(logical_name: str, source_path: str, source_candidates: tuple[str, ...]) -> str:
    if _root_cause_category(logical_name, source_candidates) == "missing local files":
        return (
            "Extract the selected IPSW into the repo-local IPSW root and rerun preflight so the manifest-selected payload "
            f"`{source_path}` can resolve without changing execution code."
        )
    if _root_cause_category(logical_name, source_candidates) == "stale legacy assumptions":
        return (
            "Normalize legacy firmware-root probing so component resolution prefers one canonical extracted-firmware root "
            "instead of mixed `resources/Firmware/Firmware/...` assumptions."
        )
    return "Tighten source-resolution rules so planning and legacy execution share one canonical payload location contract."


def _expectation_status(logical_name: str) -> str:
    return "legacy/unverified" if EXPECTATION_MODULE.get(logical_name) == "resources/img4.py" else "validated"


def _unresolved_payloads(source_checks: list[dict[str, object]]) -> list[dict[str, object]]:
    unresolved = []
    for source in source_checks:
        if source["resolved"]:
            continue
        logical_name = str(source["logical_name"])
        source_path = str(source["source_path"])
        source_candidates = tuple(str(candidate) for candidate in source["candidates"])
        unresolved.append(
            {
                "component": logical_name,
                "manifest_key": str(source["manifest_key"]),
                "relative_file": source_path,
                "parent_layout": str(Path(source_path).parent),
                "expected_source_paths": list(source_candidates),
                "derived_from": _derive_source_path(logical_name, source_path),
                "source_kind": SOURCE_KIND.get(logical_name, "local IPSW extraction"),
                "expecting_module": EXPECTATION_MODULE.get(logical_name, "unknown"),
                "expectation_status": _expectation_status(logical_name),
                "root_cause_category": _root_cause_category(logical_name, source_candidates),
                "proposed_fix": _proposed_fix(logical_name, source_path, source_candidates),
                "remediation_action": (
                    "extract IPSW"
                    if _root_cause_category(logical_name, source_candidates) == "missing local files"
                    else "update path logic"
                ),
            }
        )
    return unresolved


def _source_candidates(source_path: str) -> tuple[str, ...]:
    return (
        str(LOCAL_IPSW_DIR / source_path),
        str(RESOURCES_DIR / "Firmware" / source_path),
        str(PROJECT_ROOT / source_path),
    )


def _component_steps(logical_name: str) -> tuple[ExecutionStep, ...]:
    steps = [
        ExecutionStep(
            name="manifest-select",
            description="Resolve component path from BuildManifest for the selected board identity.",
            tool=None,
            module="odtslib.firmware_pipeline",
            status=STEP_STATUS["planning"],
        ),
        ExecutionStep(
            name="source-resolve",
            description="Resolve the planned component source into a local IPSW extraction or staged firmware location.",
            tool=None,
            module="odtslib.execution_preflight",
            status=STEP_STATUS["planning"],
        ),
    ]
    if logical_name in {"ibss", "ibec"}:
        steps.extend(
            [
                ExecutionStep(
                    name="patch-boot-image",
                    description="Patch low-level boot image before repackaging.",
                    tool="iBoot64Patcher/kairos",
                    module="resources/img4.py",
                    status=STEP_STATUS["legacy"],
                ),
                ExecutionStep(
                    name="sign-patched-image",
                    description="Create IMG4 output with signing material for the patched boot component.",
                    tool="img4tool",
                    module="resources/img4.py",
                    status=STEP_STATUS["legacy"],
                ),
                ExecutionStep(
                    name="send-to-device",
                    description="Transmit prepared boot image to the connected device during live execution.",
                    tool="irecovery",
                    module="resources/img4.py",
                    status=STEP_STATUS["live"],
                ),
            ]
        )
    elif logical_name == "kernelcache":
        steps.extend(
            [
                ExecutionStep(
                    name="unpack-kernelcache",
                    description="Unpack kernelcache to a mutable form for optional patching.",
                    tool="img4",
                    module="resources/img4.py",
                    status=STEP_STATUS["legacy"],
                ),
                ExecutionStep(
                    name="patch-kernelcache",
                    description="Apply optional AMFI-related kernel patching when requested.",
                    tool="Kernel64Patcher",
                    module="resources/img4.py",
                    status=STEP_STATUS["legacy"],
                ),
                ExecutionStep(
                    name="sign-kernelcache",
                    description="Wrap the kernelcache into a signed IMG4 artifact for boot flow use.",
                    tool="img4tool",
                    module="resources/img4.py",
                    status=STEP_STATUS["legacy"],
                ),
            ]
        )
    elif logical_name == "devicetree":
        steps.extend(
            [
                ExecutionStep(
                    name="patch-devicetree",
                    description="Apply optional DeviceTree patching for dual-boot or board-specific flow adjustments.",
                    tool="dtree_patcher",
                    module="resources/img4.py",
                    status=STEP_STATUS["legacy"],
                ),
                ExecutionStep(
                    name="sign-devicetree",
                    description="Wrap the DeviceTree payload into a signed IMG4 artifact.",
                    tool="img4tool",
                    module="resources/img4.py",
                    status=STEP_STATUS["legacy"],
                ),
            ]
        )
    else:
        steps.append(
            ExecutionStep(
                name="sign-component",
                description="Wrap the planned payload into a signed artifact for live execution.",
                tool="img4tool",
                module="resources/img4.py",
                status=STEP_STATUS["legacy"],
            )
        )
    return tuple(steps)


def _planned_components(plan: FirmwareArtifactPlan) -> tuple[PlannedComponentStep, ...]:
    return tuple(
        PlannedComponentStep(
            logical_name=component.logical_name,
            manifest_key=component.manifest_key,
            source_path=component.source_path,
            output_path=component.output_path,
            source_candidates=_source_candidates(component.source_path),
            steps=_component_steps(component.logical_name),
        )
        for component in plan.components
    )


def _required_tools(components: tuple[PlannedComponentStep, ...]) -> list[str]:
    names: list[str] = []
    for component in components:
        for step in component.steps:
            if not step.tool:
                continue
            for name in step.tool.split("/"):
                cleaned = name.strip()
                if cleaned and cleaned not in names:
                    names.append(cleaned)
    if "irecovery" not in names:
        names.append("irecovery")
    return names


def _tool_report(names: list[str]) -> list[dict[str, object]]:
    registry = ToolRegistry()
    reports: list[dict[str, object]] = []
    for name in names:
        attr = TOOL_ATTRS.get(name)
        if not attr:
            reports.append({"name": name, "runnable": False, "detail": "no wrapper registered"})
            continue
        wrapper = getattr(registry, attr)
        reports.append(asdict(wrapper.inspect()))
    return reports


def _touchpoints() -> list[dict[str, object]]:
    reports = []
    for relative_path, role, status in LEGACY_TOUCHPOINTS:
        path = PROJECT_ROOT / relative_path
        reports.append(
            asdict(
                LegacyTouchpoint(
                    path=relative_path,
                    role=role,
                    status=status,
                    exists=path.exists(),
                )
            )
        )
    return reports


def _resolve_board_config(explicit_board_config: str | None) -> tuple[str, dict[str, object] | None]:
    if explicit_board_config:
        return explicit_board_config, None

    device_report = collect_device_state_report()
    model = device_report.identifiers.get("MODEL")
    if device_report.state == DeviceStateName.IDENTIFIERS_READY.value and model:
        return str(model), {
            "state": device_report.state,
            "identifiers": device_report.identifiers,
            "selected_tool": device_report.tools[0].path if device_report.tools else None,
        }

    bdid = device_report.identifiers.get("BDID")
    if device_report.state == DeviceStateName.IDENTIFIERS_READY.value and bdid:
        short_bdid = str(bdid).replace("0x", "").replace("0X", "")[:2].upper()
        return read_board_config(short_bdid), {
            "state": device_report.state,
            "identifiers": device_report.identifiers,
            "selected_tool": device_report.tools[0].path if device_report.tools else None,
        }
    raise ODTSError(
        "Unable to resolve board configuration from the connected device. Use --board-config explicitly or connect a detectable target."
    )


def build_execution_graph(manifest: FirmwareManifest, board_config: str | None) -> dict[str, object]:
    resolved_board, device_context = _resolve_board_config(board_config)
    plan = build_artifact_plan(manifest, resolved_board)
    components = _planned_components(plan)
    return {
        "manifest": str(manifest.path),
        "board_config": resolved_board,
        "device_context": device_context,
        "identity": {
            "device_class": plan.identity.device_class,
            "board_id": plan.identity.board_id,
            "chip_id": plan.identity.chip_id,
            "variant": plan.identity.variant,
            "product_version": plan.product_version,
            "build_number": plan.build_number,
        },
        "components": [asdict(component) for component in components],
        "global_steps": [
            asdict(
                ExecutionStep(
                    name="enter-pwned-dfu",
                    description="Transition the target into the expected exploit/patched image-loading state before boot image transfer.",
                    tool="ipwndfu8012/nop_image4.py",
                    module="resources/pwn.py",
                    status=STEP_STATUS["unverified"],
                )
            ),
            asdict(
                ExecutionStep(
                    name="send-boot-chain",
                    description="Send the prepared boot chain and ramdisk payloads over irecovery in the live boot flow.",
                    tool="irecovery",
                    module="resources/img4.py",
                    status=STEP_STATUS["unverified"],
                )
            ),
        ],
    }


def build_execution_preflight(manifest: FirmwareManifest, board_config: str | None) -> dict[str, object]:
    graph = build_execution_graph(manifest, board_config)
    required_tools = _required_tools(tuple(PlannedComponentStep(**{
        **component,
        "steps": tuple(ExecutionStep(**step) for step in component["steps"]),
        "source_candidates": tuple(component["source_candidates"]),
    }) for component in graph["components"]))

    source_checks = []
    blockers: list[str] = []
    for component in graph["components"]:
        existing_candidates = [candidate for candidate in component["source_candidates"] if Path(candidate).exists()]
        source_checks.append(
            {
                "logical_name": component["logical_name"],
                "manifest_key": component["manifest_key"],
                "source_path": component["source_path"],
                "candidates": component["source_candidates"],
                "resolved": bool(existing_candidates),
                "resolved_candidates": existing_candidates,
            }
        )
        if not existing_candidates:
            blockers.append(
                f"{component['logical_name']}: no local source payload found at any planned candidate path"
            )

    static_resources = []
    for name, path in {
        "ramdisk_source": RESOURCES_DIR / "018-75901-013.dmg",
        "bootlogo": RESOURCES_DIR / "bootlogo.png",
        "shsh": SHSH_PATH,
        "manifest": manifest.path,
    }.items():
        exists = Path(path).exists()
        static_resources.append({"name": name, "path": str(path), "exists": exists})
        if name == "shsh" and not exists:
            blockers.append("signing material missing: resources/shsh.shsh is not present")

    tool_reports = _tool_report(required_tools)
    for tool in tool_reports:
        if not tool.get("runnable"):
            blockers.append(f"tool not runnable: {tool['name']} ({tool.get('detail')})")

    touchpoints = _touchpoints()
    for touchpoint in touchpoints:
        if not touchpoint["exists"]:
            blockers.append(f"legacy module missing: {touchpoint['path']}")

    unresolved_payloads = _unresolved_payloads(source_checks)

    readiness = _readiness_summary(
        blockers=blockers,
        graph=graph,
        tool_reports=tool_reports,
        touchpoints=touchpoints,
    )

    return {
        "graph": graph,
        "required_tools": tool_reports,
        "source_checks": source_checks,
        "static_resources": static_resources,
        "legacy_touchpoints": touchpoints,
        "unresolved_payloads": unresolved_payloads,
        "blockers": blockers,
        "ready_for_live_execution": not blockers,
        "readiness": asdict(readiness),
    }


def _readiness_summary(
    *,
    blockers: list[str],
    graph: dict[str, object],
    tool_reports: list[dict[str, object]],
    touchpoints: list[dict[str, object]],
) -> ReadinessSummary:
    first_step = graph["global_steps"][0]
    first_step_name = first_step["name"]
    first_step_tool = first_step.get("tool")
    first_step_module = first_step.get("module")

    tool_names = {tool["name"]: tool for tool in tool_reports}
    touchpoint_names = {touchpoint["path"]: touchpoint for touchpoint in touchpoints}

    first_step_classification = "unverified"
    if first_step_tool == "irecovery" and tool_names.get("irecovery", {}).get("runnable"):
        first_step_classification = "legacy but observable" if first_step["status"] == "legacy" else "validated"
    elif first_step_module and touchpoint_names.get(first_step_module, {}).get("exists"):
        if any("tool not runnable" in blocker for blocker in blockers):
            first_step_classification = "blocked"
        elif first_step["status"] == "legacy":
            first_step_classification = "legacy but observable"
        elif first_step["status"] == "unverified":
            first_step_classification = "unverified"

    payload_only_blockers = bool(blockers) and all("no local source payload found" in blocker for blocker in blockers)

    if any("tool not runnable" in blocker for blocker in blockers) or any("legacy module missing" in blocker for blocker in blockers):
        level = "not ready for live testing"
        rationale = "Execution-side prerequisites are incomplete because at least one required tool or legacy module is unavailable."
        first_candidate = None
        operator_action_needed = "Restore the missing execution-side prerequisites before reconsidering any live test."
        payloads_enable_live_testing = False
    elif blockers:
        level = "ready for planning only"
        rationale = "Planning and preflight are working, but unresolved blockers remain before any controlled live step should be attempted."
        first_candidate = None
        operator_action_needed = "Provide or extract the manifest-selected local payload files into the expected canonical layout and rerun preflight."
        payloads_enable_live_testing = first_step_classification in {"validated", "legacy but observable"}
    elif first_step_classification in {"validated", "legacy but observable"}:
        level = "ready for controlled live step testing"
        rationale = "Planning is complete and the first execution-side step is observable with no unresolved preflight blockers."
        first_candidate = first_step_name
        operator_action_needed = "Capture the declared logs and keep to the documented stop conditions before the first controlled live step."
        payloads_enable_live_testing = True
    else:
        level = "ready for planning only"
        rationale = "Planning is complete, but the first execution-side step is still unverified."
        first_candidate = None
        operator_action_needed = "Validate or instrument the first execution-side step before treating the repo as ready for controlled live testing."
        payloads_enable_live_testing = False

    return ReadinessSummary(
        level=level,
        rationale=rationale,
        only_blocker_is_missing_payload_material=payload_only_blockers,
        operator_action_needed=operator_action_needed,
        would_valid_local_payloads_enable_live_step_testing=payloads_enable_live_testing,
        first_execution_step_name=first_step_name,
        first_execution_step_classification=first_step_classification,
        first_execution_step_tool=first_step_tool,
        first_execution_step_module=first_step_module,
        first_safe_live_test_candidate=first_candidate,
        stop_conditions=(
            "unexpected device disconnect or mode transition",
            "missing planned payload source resolution",
            "any loader or runtime failure from selected tools",
            "unexpected prompt, hang, or uncontrolled retry loop in legacy execution code",
        ),
    )


def render_execution_graph(graph: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(graph, indent=2, sort_keys=True)

    lines = [
        "Execution graph",
        f"Manifest: {graph['manifest']}",
        f"Board: {graph['board_config']}",
        f"Identity: {graph['identity']['device_class']} board={graph['identity']['board_id']} chip={graph['identity']['chip_id']}",
    ]
    if graph.get("device_context"):
        lines.append(f"Connected device model: {graph['device_context']['identifiers'].get('MODEL')}")
    lines.append("Components:")
    for component in graph["components"]:
        lines.append(
            f"  - {component['logical_name']}: source={component['source_path']} output={component['output_path']}"
        )
        for step in component["steps"]:
            lines.append(
                f"    step={step['name']} status={step['status']} tool={step['tool'] or 'none'} module={step['module'] or 'none'}"
            )
    lines.append("Global steps:")
    for step in graph["global_steps"]:
        lines.append(
            f"  - {step['name']}: status={step['status']} tool={step['tool'] or 'none'} module={step['module'] or 'none'}"
        )
    return "\n".join(lines)


def render_execution_preflight(preflight: dict[str, object], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(preflight, indent=2, sort_keys=True)

    lines = [
        "Execution preflight",
        f"Ready for live execution: {preflight['ready_for_live_execution']}",
        f"Readiness level: {preflight['readiness']['level']}",
        f"Readiness rationale: {preflight['readiness']['rationale']}",
        f"Only blocker is missing payload material: {preflight['readiness']['only_blocker_is_missing_payload_material']}",
        f"Operator action needed: {preflight['readiness']['operator_action_needed']}",
        f"Would valid local payloads enable live step testing: {preflight['readiness']['would_valid_local_payloads_enable_live_step_testing']}",
        f"Board: {preflight['graph']['board_config']}",
        "First execution-side step:",
        (
            f"  - {preflight['readiness']['first_execution_step_name']}: "
            f"classification={preflight['readiness']['first_execution_step_classification']} "
            f"tool={preflight['readiness']['first_execution_step_tool'] or 'none'} "
            f"module={preflight['readiness']['first_execution_step_module'] or 'none'}"
        ),
        "Required tools:",
    ]
    for tool in preflight["required_tools"]:
        lines.append(
            f"  - {tool['name']}: runnable={tool.get('runnable')} path={tool.get('path')} selected={tool.get('selected_candidate')}"
        )
    lines.append("Source checks:")
    for source in preflight["source_checks"]:
        lines.append(
            f"  - {source['logical_name']}: resolved={source['resolved']} source={source['source_path']}"
        )
    lines.append("Legacy touchpoints:")
    for touchpoint in preflight["legacy_touchpoints"]:
        lines.append(
            f"  - {touchpoint['path']}: status={touchpoint['status']} exists={touchpoint['exists']} role={touchpoint['role']}"
        )
    lines.append("Unresolved payloads:")
    for payload in preflight["unresolved_payloads"] or ["none"]:
        if isinstance(payload, str):
            lines.append(f"  - {payload}")
            continue
        lines.append(
            f"  - {payload['component']}: kind={payload['source_kind']} "
            f"module={payload['expecting_module']} status={payload['expectation_status']}"
        )
        lines.append(f"    manifest_key={payload['manifest_key']}")
        lines.append(f"    relative_file={payload['relative_file']}")
        lines.append(f"    parent_layout={payload['parent_layout']}")
        lines.append(f"    cause={payload['root_cause_category']}")
        lines.append(f"    action={payload['remediation_action']}")
        lines.append(f"    derived={payload['derived_from']}")
        lines.append(f"    fix={payload['proposed_fix']}")
        for candidate in payload["expected_source_paths"]:
            lines.append(f"    expected={candidate}")
    lines.append("Blockers:")
    for blocker in preflight["blockers"] or ["none"]:
        lines.append(f"  - {blocker}")
    lines.append("Stop conditions:")
    for condition in preflight["readiness"]["stop_conditions"]:
        lines.append(f"  - {condition}")
    return "\n".join(lines)
