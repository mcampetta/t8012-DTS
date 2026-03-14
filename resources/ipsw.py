from __future__ import annotations

import plistlib
import shutil
from pathlib import Path
from zipfile import ZipFile, is_zipfile


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCAL_IPSW_DIR = PROJECT_ROOT / "IPSW"


def read_manifest(path: str | Path, return_version: bool):
    manifest_path = Path(path)
    with manifest_path.open("rb") as handle:
        plist = plistlib.load(handle)

    if return_version:
        return plist["ProductVersion"]
    return plist["SupportedProductTypes"]


def readmanifest(path, flag):
    return read_manifest(path, flag)


def unzip_ipsw(path: str | Path) -> str:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"IPSW path does not exist: {source}")
    if not is_zipfile(source):
        raise ValueError(f"{source} is not a valid IPSW/zip archive.")

    if LOCAL_IPSW_DIR.exists():
        shutil.rmtree(LOCAL_IPSW_DIR)
    LOCAL_IPSW_DIR.mkdir(parents=True, exist_ok=True)

    with ZipFile(source, "r") as archive:
        archive.extractall(LOCAL_IPSW_DIR)

    manifest_path = LOCAL_IPSW_DIR / "BuildManifest.plist"
    if not manifest_path.exists():
        raise FileNotFoundError("Extracted IPSW does not contain BuildManifest.plist.")

    return str(read_manifest(manifest_path, return_version=True))


def unzipIPSW(path):
    return unzip_ipsw(path)
