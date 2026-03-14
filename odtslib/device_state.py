from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum

from .device import parse_irecovery_query
from .tool_wrappers import IRecoveryTool, ToolRegistry


class DeviceStateName(str, Enum):
    NO_DEVICE = "no_device"
    USB_PRESENT_UNKNOWN = "usb_present_unknown"
    DFU_DETECTED = "dfu_detected"
    RECOVERY_DETECTED = "recovery_detected"
    IDENTIFIERS_PARTIAL = "identifiers_partial"
    IDENTIFIERS_READY = "identifiers_ready"
    TOOL_COMM_FAILURE = "tool_comm_failure"
    UNSUPPORTED_STATE = "unsupported_state"


@dataclass(frozen=True)
class DeviceStateDefinition:
    name: DeviceStateName
    meaning: str
    likely_next_step: str
    likely_failure_causes: tuple[str, ...]


STATE_DEFINITIONS = {
    DeviceStateName.NO_DEVICE: DeviceStateDefinition(
        DeviceStateName.NO_DEVICE,
        "No relevant device could be detected by the available inspection tools.",
        "Verify cable, host USB connectivity, and whether the target Mac is in DFU mode.",
        ("device not connected", "bad cable", "wrong device mode"),
    ),
    DeviceStateName.USB_PRESENT_UNKNOWN: DeviceStateDefinition(
        DeviceStateName.USB_PRESENT_UNKNOWN,
        "A potentially relevant device may be present, but the current tooling cannot classify it confidently.",
        "Recheck DFU/recovery mode and run the monitor again.",
        ("partial tool output", "unexpected device state", "unsupported identifiers"),
    ),
    DeviceStateName.DFU_DETECTED: DeviceStateDefinition(
        DeviceStateName.DFU_DETECTED,
        "The device appears to be in DFU mode or a pre-recovery state that exposes low-level identifiers.",
        "If identifiers are complete, proceed to dry-run validation. Otherwise confirm DFU stability.",
        ("transient USB state", "partial DFU enumeration"),
    ),
    DeviceStateName.RECOVERY_DETECTED: DeviceStateDefinition(
        DeviceStateName.RECOVERY_DETECTED,
        "The device appears visible through irecovery in recovery-style communication.",
        "Proceed with dry-run workflow validation if identifiers are sufficient.",
        ("device already transitioned out of DFU", "recovery-only state"),
    ),
    DeviceStateName.IDENTIFIERS_PARTIAL: DeviceStateDefinition(
        DeviceStateName.IDENTIFIERS_PARTIAL,
        "Some identifying values were read, but not enough for confident workflow progression.",
        "Retry device-state inspection and confirm ECID/BDID availability.",
        ("irecovery output incomplete", "unstable connection"),
    ),
    DeviceStateName.IDENTIFIERS_READY: DeviceStateDefinition(
        DeviceStateName.IDENTIFIERS_READY,
        "Required identifiers were read successfully and the device appears compatible with later dry-run stages.",
        "Proceed to `--dry-run` or `--validate-firmware` checks before any live action.",
        ("none"),
    ),
    DeviceStateName.TOOL_COMM_FAILURE: DeviceStateDefinition(
        DeviceStateName.TOOL_COMM_FAILURE,
        "The inspection tool exists but could not communicate with the connected device.",
        "Check host permissions, macOS compatibility of the bundled binary, and device mode.",
        ("irecovery/tool execution failure", "host compatibility issue", "USB communication problem"),
    ),
    DeviceStateName.UNSUPPORTED_STATE: DeviceStateDefinition(
        DeviceStateName.UNSUPPORTED_STATE,
        "The device reported identifiers or behavior outside the currently understood T2 workflow.",
        "Capture the output and compare against expected T2 identifiers before proceeding.",
        ("unexpected CPID/BDID", "different device family", "unsupported runtime state"),
    ),
}


@dataclass
class ToolProbe:
    tool: str
    success: bool
    stdout: str
    stderr: str
    returncode: int
    detail: str


@dataclass
class DeviceStateReport:
    state: str
    meaning: str
    evidence: list[str]
    identifiers: dict[str, str | None]
    tools: list[ToolProbe]
    likely_next_step: str
    likely_failure_causes: list[str]
    compatible_with_later_stages: bool


def classify_device_state(parsed_identifiers: dict[str, str], tool_success: bool) -> DeviceStateName:
    if not tool_success:
        return DeviceStateName.TOOL_COMM_FAILURE
    if not parsed_identifiers:
        return DeviceStateName.NO_DEVICE

    has_ecid = bool(parsed_identifiers.get("ECID"))
    has_bdid = bool(parsed_identifiers.get("BDID"))
    has_cpid = bool(parsed_identifiers.get("CPID"))
    product = parsed_identifiers.get("MODEL") or parsed_identifiers.get("PRODUCT")

    if has_ecid and has_bdid:
        return DeviceStateName.IDENTIFIERS_READY
    if has_ecid or has_bdid or has_cpid:
        return DeviceStateName.IDENTIFIERS_PARTIAL
    if product:
        return DeviceStateName.RECOVERY_DETECTED
    return DeviceStateName.USB_PRESENT_UNKNOWN


def inspect_device_state(*, json_output: bool = False, verbose: bool = False) -> str | DeviceStateReport:
    tools = ToolRegistry()
    irecovery = tools.irecovery

    probe: ToolProbe
    parsed: dict[str, str]
    evidence: list[str] = []
    try:
        result = irecovery.query(dry_run=False)
        probe = ToolProbe(
            tool="irecovery",
            success=result.returncode == 0,
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            detail="query succeeded" if result.returncode == 0 else "query returned non-zero exit",
        )
        parsed = parse_irecovery_query(result.stdout)
        if result.stdout.strip():
            evidence.append("irecovery produced query output")
        if parsed.get("ECID"):
            evidence.append(f"ECID detected: {parsed['ECID']}")
        if parsed.get("BDID"):
            evidence.append(f"BDID detected: {parsed['BDID']}")
        if parsed.get("CPID"):
            evidence.append(f"CPID detected: {parsed['CPID']}")
    except Exception as exc:
        probe = ToolProbe(
            tool="irecovery",
            success=False,
            stdout="",
            stderr=str(exc),
            returncode=1,
            detail="query failed",
        )
        parsed = {}
        evidence.append(f"irecovery query failed: {exc}")

    state_name = classify_device_state(parsed, probe.success)
    definition = STATE_DEFINITIONS[state_name]
    compatible = state_name == DeviceStateName.IDENTIFIERS_READY

    report = DeviceStateReport(
        state=state_name.value,
        meaning=definition.meaning,
        evidence=evidence,
        identifiers={
            "ECID": parsed.get("ECID"),
            "BDID": parsed.get("BDID"),
            "CPID": parsed.get("CPID"),
            "MODEL": parsed.get("MODEL") or parsed.get("PRODUCT"),
        },
        tools=[probe],
        likely_next_step=definition.likely_next_step,
        likely_failure_causes=list(definition.likely_failure_causes),
        compatible_with_later_stages=compatible,
    )

    if json_output:
        return json.dumps(asdict(report), indent=2, sort_keys=True)

    lines = [
        f"Device state: {report.state}",
        f"Meaning: {report.meaning}",
        f"Compatible with later stages: {report.compatible_with_later_stages}",
        "Evidence:",
    ]
    for item in report.evidence or ["No evidence collected."]:
        lines.append(f"  - {item}")
    lines.append("Identifiers:")
    for key, value in report.identifiers.items():
        lines.append(f"  - {key}: {value or 'not found'}")
    lines.append("Tools:")
    for tool in report.tools:
        lines.append(f"  - {tool.tool}: success={tool.success} returncode={tool.returncode} detail={tool.detail}")
        if verbose:
            if tool.stdout.strip():
                lines.append("    stdout:")
                for line in tool.stdout.strip().splitlines():
                    lines.append(f"      {line}")
            if tool.stderr.strip():
                lines.append("    stderr:")
                for line in tool.stderr.strip().splitlines():
                    lines.append(f"      {line}")
    lines.append(f"Next step: {report.likely_next_step}")
    lines.append("Likely failure causes:")
    for cause in report.likely_failure_causes:
        lines.append(f"  - {cause}")
    return "\n".join(lines)
