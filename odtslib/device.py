from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .config import A10_A11_MODELS, DEVICE_MAP_PATH
from .exceptions import DeviceStateError


@dataclass
class DeviceInfo:
    ecid: str
    bdid: str
    board_config: str


def is_a10_a11_or_t2(device_model: str) -> bool:
    return device_model in A10_A11_MODELS


def parse_irecovery_query(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in output.splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        values[key.strip().upper()] = value.strip()
    return values


def read_board_config(short_bdid: str, device_map_path: Path = DEVICE_MAP_PATH) -> str:
    pattern = re.compile(rf"\b{re.escape(short_bdid.upper())}\b", re.IGNORECASE)
    with device_map_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not pattern.search(line):
                continue
            parts = [part for part in re.split(r"\s+", line.strip()) if part]
            for part in parts:
                if part.lower().endswith("ap"):
                    return part
    raise DeviceStateError(f"Unable to resolve board configuration for BDID {short_bdid}.")
