from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import BOOTLOGO_PATH, MANIFEST_PATH, RESOURCES_DIR, SHSH_PATH, STAGED_FILES_DIR
from .firmware_manifest import BuildIdentity, FirmwareManifest, load_firmware_manifest
from .stage_model import StageDefinition, StageResult

COMPONENT_RULES = {
    "ibec": ("iBEC",),
    "ibss": ("iBSS",),
    "kernelcache": ("KernelCache", "RestoreKernelCache"),
    "devicetree": ("DeviceTree", "RestoreDeviceTree"),
    "trustcache": ("StaticTrustCache", "TrustCache"),
    "aopfw": ("AOP",),
    "isp": ("ISP", "ISPFirmware"),
    "callan": ("CallanFirmware",),
    "touch": ("Multitouch", "MultitouchFirmware"),
    "stockholm": ("Stockholm", "SE,Firmware"),
}


@dataclass(frozen=True)
class ComponentSelection:
    logical_name: str
    manifest_key: str
    source_path: str
    output_path: str
    personalized: bool


@dataclass(frozen=True)
class FirmwareArtifactPlan:
    board_config: str
    product_version: str | None
    build_number: str | None
    identity: BuildIdentity
    components: tuple[ComponentSelection, ...]
    staged_outputs: tuple[str, ...]


PIPELINE_STAGES = (
    StageDefinition(
        name="manifest-load",
        required_inputs=("manifest_path",),
        expected_outputs=("firmware_manifest",),
        failure_modes=("manifest file missing", "plist parse failure"),
        dry_run_safe=True,
        description="Load and parse BuildManifest.plist into structured identities and components.",
    ),
    StageDefinition(
        name="board-select",
        required_inputs=("firmware_manifest", "board_config"),
        expected_outputs=("build_identity",),
        failure_modes=("board config absent from manifest",),
        dry_run_safe=True,
        description="Match the resolved board configuration to a BuildIdentity.",
    ),
    StageDefinition(
        name="artifact-plan",
        required_inputs=("build_identity", "resource_mode"),
        expected_outputs=("firmware_artifact_plan",),
        failure_modes=("required component path missing", "missing local IPSW payload"),
        dry_run_safe=True,
        description="Resolve board-specific firmware components and their staged artifact targets.",
    ),
    StageDefinition(
        name="tool-invocation-plan",
        required_inputs=("firmware_artifact_plan", "shsh", "boot_args"),
        expected_outputs=("tool_plan",),
        failure_modes=("required external tool missing",),
        dry_run_safe=True,
        description="Describe which external binaries would be invoked to patch, sign, and stage boot artifacts.",
    ),
)


def _output_for(logical_name: str, source_path: str) -> str:
    suffix = Path(source_path).suffix or ".im4p"
    if logical_name in {"ibec", "ibss", "kernelcache", "devicetree", "trustcache", "aopfw", "isp", "callan", "touch", "stockholm"}:
        stem_map = {
            "kernelcache": "kernel",
            "devicetree": "devicetree",
            "trustcache": "trustcache",
            "aopfw": "aopfw",
            "callan": "callan",
            "touch": "touch",
            "stockholm": "stockholm",
            "isp": "isp",
            "ibec": "ibec",
            "ibss": "ibss",
        }
        return str(STAGED_FILES_DIR / f"{stem_map[logical_name]}{suffix}")
    return str(STAGED_FILES_DIR / Path(source_path).name)


def load_manifest_for_planning(path: str | Path = MANIFEST_PATH) -> FirmwareManifest:
    return load_firmware_manifest(path)


def select_identity(manifest: FirmwareManifest, board_config: str) -> BuildIdentity:
    return manifest.find_identity(board_config=board_config)


def build_artifact_plan(manifest: FirmwareManifest, board_config: str) -> FirmwareArtifactPlan:
    identity = select_identity(manifest, board_config)
    selections: list[ComponentSelection] = []
    for logical_name, manifest_keys in COMPONENT_RULES.items():
        component = next((identity.component(key) for key in manifest_keys if identity.component(key)), None)
        if not component or not component.path:
            continue
        selections.append(
            ComponentSelection(
                logical_name=logical_name,
                manifest_key=component.key,
                source_path=component.path,
                output_path=_output_for(logical_name, component.path),
                personalized=component.personalized,
            )
        )
    staged_outputs = tuple(item.output_path for item in selections)
    return FirmwareArtifactPlan(
        board_config=board_config,
        product_version=manifest.product_version,
        build_number=identity.build_number,
        identity=identity,
        components=tuple(selections),
        staged_outputs=staged_outputs,
    )


def generate_stage_results(manifest: FirmwareManifest, board_config: str) -> tuple[StageResult, ...]:
    identity = select_identity(manifest, board_config)
    plan = build_artifact_plan(manifest, board_config)
    return (
        StageResult(PIPELINE_STAGES[0], "ok", f"Loaded {len(manifest.build_identities)} build identities.", {"manifest_path": str(manifest.path)}),
        StageResult(PIPELINE_STAGES[1], "ok", f"Selected board {board_config}.", {"device_class": identity.device_class}),
        StageResult(PIPELINE_STAGES[2], "ok", f"Planned {len(plan.components)} component artifacts.", {"components": str(len(plan.components))}),
        StageResult(
            PIPELINE_STAGES[3],
            "ok",
            "Tool invocation planning is available without executing device actions.",
            {"staged_outputs": str(len(plan.staged_outputs))},
        ),
    )


def render_plan_report(plan: FirmwareArtifactPlan) -> dict[str, object]:
    tool_plan = [
        {"tool": "img4tool", "purpose": "extract and sign IMG4 payload metadata"},
        {"tool": "irecovery", "purpose": "send prepared images and commands to the device"},
    ]
    if any(component.logical_name in {"ibec", "ibss"} for component in plan.components):
        tool_plan.append({"tool": "iBoot64Patcher/kairos", "purpose": "patch iBSS/iBEC boot chain images"})
    if any(component.logical_name == "kernelcache" for component in plan.components):
        tool_plan.append({"tool": "img4", "purpose": "unpack kernelcache for optional patching"})
        tool_plan.append({"tool": "Kernel64Patcher", "purpose": "apply optional AMFI-related kernel patching"})
    if any(component.logical_name == "devicetree" for component in plan.components):
        tool_plan.append({"tool": "dtree_patcher", "purpose": "apply optional dual-boot DeviceTree patching"})
    if any(component.logical_name == "bootlogo" for component in plan.components):
        tool_plan.append({"tool": "ibootim", "purpose": "convert PNG boot logo to iBoot image format"})

    return {
        "board_config": plan.board_config,
        "product_version": plan.product_version,
        "build_number": plan.build_number,
        "identity": {
            "device_class": plan.identity.device_class,
            "board_id": plan.identity.board_id,
            "chip_id": plan.identity.chip_id,
            "variant": plan.identity.variant,
        },
        "components": [asdict(component) for component in plan.components],
        "staged_outputs": list(plan.staged_outputs),
        "static_resources": {
            "bootlogo": str(BOOTLOGO_PATH),
            "shsh": str(SHSH_PATH),
            "manifest": str(MANIFEST_PATH),
            "ramdisk_source": str(RESOURCES_DIR / "018-75901-013.dmg"),
        },
        "tool_invocation_plan": tool_plan,
    }
