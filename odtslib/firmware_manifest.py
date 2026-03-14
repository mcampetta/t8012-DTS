from __future__ import annotations

import plistlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ManifestComponent:
    key: str
    path: str | None
    personalized: bool
    loaded_by_iboot: bool | None = None


@dataclass(frozen=True)
class BuildIdentity:
    device_class: str
    board_id: str | None
    chip_id: str | None
    variant: str | None
    build_number: str | None
    build_train: str | None
    components: dict[str, ManifestComponent] = field(default_factory=dict)

    def component(self, key: str) -> ManifestComponent | None:
        return self.components.get(key)


@dataclass(frozen=True)
class FirmwareManifest:
    path: Path
    product_version: str | None
    product_build_version: str | None
    supported_product_types: tuple[str, ...]
    build_identities: tuple[BuildIdentity, ...]

    def find_identity(self, *, board_config: str) -> BuildIdentity:
        for identity in self.build_identities:
            if identity.device_class == board_config:
                return identity
        raise KeyError(f"No BuildIdentity found for board config {board_config}.")


def _component_from_manifest(key: str, value: dict[str, Any]) -> ManifestComponent:
    info = value.get("Info", {}) if isinstance(value, dict) else {}
    return ManifestComponent(
        key=key,
        path=info.get("Path"),
        personalized=bool(info.get("Personalize", False)),
        loaded_by_iboot=info.get("IsLoadedByiBoot"),
    )


def _identity_from_dict(data: dict[str, Any]) -> BuildIdentity:
    info = data.get("Info", {})
    manifest = data.get("Manifest", {})
    components = {
        key: _component_from_manifest(key, value)
        for key, value in manifest.items()
        if isinstance(value, dict)
    }
    return BuildIdentity(
        device_class=info.get("DeviceClass", ""),
        board_id=data.get("ApBoardID"),
        chip_id=data.get("ApChipID"),
        variant=info.get("Variant"),
        build_number=info.get("BuildNumber"),
        build_train=info.get("BuildTrain"),
        components=components,
    )


def load_firmware_manifest(path: str | Path) -> FirmwareManifest:
    manifest_path = Path(path)
    with manifest_path.open("rb") as handle:
        plist = plistlib.load(handle)

    identities = tuple(_identity_from_dict(item) for item in plist.get("BuildIdentities", []))
    supported = tuple(plist.get("SupportedProductTypes", []))
    return FirmwareManifest(
        path=manifest_path,
        product_version=plist.get("ProductVersion"),
        product_build_version=plist.get("ProductBuildVersion"),
        supported_product_types=supported,
        build_identities=identities,
    )

