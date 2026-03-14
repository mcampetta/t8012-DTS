from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StageDefinition:
    name: str
    required_inputs: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    failure_modes: tuple[str, ...]
    dry_run_safe: bool
    description: str


@dataclass
class StageResult:
    stage: StageDefinition
    status: str
    details: str
    produced_outputs: dict[str, str] = field(default_factory=dict)

