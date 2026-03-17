from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESOURCES_DIR = PROJECT_ROOT / "resources"
STAGED_FILES_DIR = RESOURCES_DIR / "StagedFiles"
BIN_DIR = RESOURCES_DIR / "bin"
LOCAL_IPSW_DIR = PROJECT_ROOT / "IPSW"
DEVICE_MAP_PATH = RESOURCES_DIR / "device_map.txt"
BOOTLOGO_PATH = RESOURCES_DIR / "bootlogo.png"
SHSH_PATH = RESOURCES_DIR / "shsh.shsh"
SHSH_METADATA_PATH = RESOURCES_DIR / "shsh.metadata.json"
IM4M_PATH = RESOURCES_DIR / "IM4M"
MANIFEST_PATH = RESOURCES_DIR / "manifest.plist"

TOOL_VERSION = "0.0.1-modernized"
SUPPORTED_HOST = "Darwin"
SUPPORTED_T2_MODELS = {"iBridge2,5"}
A10_A11_MODELS = {
    "iPhone9,1",
    "iPhone9,2",
    "iPhone9,3",
    "iPhone9,4",
    "iPhone10,1",
    "iPhone10,2",
    "iPhone10,3",
    "iPhone10,4",
    "iPhone10,5",
    "iPhone10,6",
    "iBridge2,5",
}

STAGED_ARTIFACTS = [
    "resources/StagedFiles/devicetree.im4p",
    "resources/StagedFiles/devicetree.img4",
    "resources/StagedFiles/ibec.im4p",
    "resources/StagedFiles/ibec.img4",
    "resources/StagedFiles/ibec.raw",
    "resources/StagedFiles/ibec.pwn",
    "resources/StagedFiles/ibec.patched",
    "resources/StagedFiles/ibss.im4p",
    "resources/StagedFiles/ibss.img4",
    "resources/StagedFiles/isp.im4p",
    "resources/StagedFiles/isp.img4",
    "resources/StagedFiles/ibss.raw",
    "resources/StagedFiles/ibss.pwn",
    "resources/StagedFiles/ibss.patched",
    "resources/StagedFiles/kernel.im4p",
    "resources/StagedFiles/kernel.img4",
    "resources/StagedFiles/kernel.raw",
    "resources/StagedFiles/kernel.patched",
    "resources/StagedFiles/kernel.compressed",
    "resources/StagedFiles/manifest.plist",
    "resources/StagedFiles/shsh.shsh",
    "resources/StagedFiles/IM4M",
    "resources/StagedFiles/devicetree.raw",
    "resources/StagedFiles/devicetree.patched",
    "resources/StagedFiles/trustcache.im4p",
    "resources/StagedFiles/trustcache.img4",
    "resources/StagedFiles/bootlogo.im4p",
    "resources/StagedFiles/bootlogo.ibootim",
    "resources/StagedFiles/bootlogo.img4",
    "resources/StagedFiles/aopfw.img4",
    "resources/StagedFiles/aopfw.im4p",
    "resources/StagedFiles/touch.im4p",
    "resources/StagedFiles/touch.img4",
    "resources/StagedFiles/callan.im4p",
    "resources/StagedFiles/callan.img4",
    "resources/StagedFiles/ramdisk.img4",
    "resources/shsh.shsh",
    "resources/IM4M",
]

EXPECTED_RUNTIME_FILES = [
    "odts.py",
    "README.md",
    "resources/bin/img4tool",
    "resources/bin/irecovery",
    "resources/bin/tsschecker",
    "resources/bin/iBoot64Patcher",
    "resources/bin/ibootim",
    "resources/bin/img4",
    "resources/device_map.txt",
    "resources/018-75901-013.dmg",
    "resources/bootlogo.png",
    "resources/ipwndfu/checkm8.py",
    "resources/ipwndfu8012/ipwndfu",
    "resources/ipwndfu8012/nop_image4.py",
]

LEGACY_PYTHON2_PATHS = [
    "resources/ipwndfu/dfu2.py",
    "resources/ipwndfu/rmsigchks.py",
    "resources/ipwndfu/usbexec2.py",
    "resources/ipwndfu/utilities.py",
    "resources/ipwndfu8012",
]

NETWORK_ENDPOINTS = {
    "ipsw_api": "https://api.ipsw.me/v4/device/{device}?type=ipsw",
    "ipsw_archive": "remote zip extraction from IPSW URLs returned by ipsw.me",
    "iphonewiki": "https://www.theiphonewiki.com/",
    "legacy_fix_img4tool": "https://github.com/tihmstar/img4tool/releases/download/182/buildroot_macos-latest.zip",
    "legacy_fix_irecovery": "https://github.com/libimobiledevice/libirecovery/archive/master.zip",
    "legacy_fix_homebrew": "https://raw.githubusercontent.com/Homebrew/install/master/install.sh",
    "legacy_fix_fugu": "https://github.com/LinusHenze/Fugu/releases/download/v0.4/Fugu_v0.4.zip",
}

FETCHABLE_RESOURCES = {
    "fugu_8010_binary": {
        "path": "resources/Fugu_8010/Fugu",
        "url": "https://github.com/LinusHenze/Fugu/releases/download/v0.4/Fugu_v0.4.zip",
        "kind": "zip-member",
        "members": {
            "fugu/Fugu": "resources/Fugu_8010/Fugu",
            "fugu/shellcode": "resources/Fugu_8010/shellcode",
        },
        "note": "Legacy Fugu payload used for CPID:8010 flows.",
    },
    "img4tool_binary": {
        "path": "resources/bin/img4tool",
        "url": "https://github.com/tihmstar/img4tool/releases/download/182/buildroot_macos-latest.zip",
        "kind": "zip-member",
        "members": {
            "buildroot_macos-latest/usr/local/bin/img4tool": "resources/bin/img4tool",
        },
        "note": "Repo-local img4tool binary only; no /usr/local headers or libraries are installed.",
    },
}

MANUAL_RESOURCES = {
    "irecovery_binary": {
        "path": "resources/bin/irecovery",
        "reason": "No safe repo-local binary source is bundled here; the legacy flow built libirecovery from source and installed it system-wide.",
    }
}
