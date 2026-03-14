# ODTS Architecture

## What This Tool Is Intended To Do

ODTS is intended to automate a tethered boot workflow for checkm8-vulnerable T2 (`T8012`) devices, specifically to boot a signed-and-patched ramdisk environment that exposes internal storage for data transfer or recovery work.

At a high level, the tool tries to:

1. identify a connected DFU device
2. determine its hardware identity (`ECID`, `BDID`, board config)
3. obtain signing material (`SHSH`)
4. obtain the correct firmware components from an IPSW
5. decrypt and patch boot chain components (`iBSS`, `iBEC`, DeviceTree, trustcache, kernel)
6. repackage those components into IMG4 containers signed with the ticket
7. exploit the device into pwned DFU / patched image-loading state
8. send a boot chain and ramdisk over `irecovery`
9. rely on the booted environment and macOS to expose/mount storage

The codebase only partially automates the final “mount volume” outcome. The implemented automation focuses mostly on staging firmware and booting the ramdisk.

## System Overview

The repository is organized around one orchestration script and several low-level helper layers:

- `odts.py`
  - top-level CLI/orchestration entrypoint
- `resources/pwn.py`
  - exploit orchestration and device-state transitions into pwned DFU
- `resources/img4.py`
  - the main firmware staging, patching, packaging, and boot-sending pipeline
- `resources/ipsw.py`
  - local IPSW extraction and manifest reading
- `iospythontools/` and `resources/iospythontools/`
  - IPSW metadata lookup, remote archive extraction, iPhone Wiki parsing
- `resources/ipwndfu/` and `resources/ipwndfu8012/`
  - vendored low-level exploit and USB communication code
- `resources/bin/`
  - vendored native utilities such as `img4tool`, `irecovery`, patchers, and exploit helpers

The first-party Python code is mostly glue around external tooling.

## Intended Execution Flow

## Stage 1: CLI Entry And Mode Selection

### Purpose

Choose between:

- remote IPSW mode (`-i DEVICE IOS`)
- local IPSW mode (`-q PATH DEVICE`)
- pwn-only mode (`-p`)
- optional patching modes (`--amfi`, `--dualboot`, custom boot logo, debug boot args)

### Implemented In

- `odts.py`

### Notes

- Historically this was a monolithic imperative entrypoint.
- The original code mixed setup, validation, exploitation, and booting in one control path.

## Stage 2: Device Detection And Device State Query

### Purpose

Talk to the connected device in DFU or recovery mode and determine:

- whether a device is present
- its serial/USB identity
- `ECID`
- `BDID`
- whether it is already in `PWND:[checkm8]` state

### Implemented In

- `resources/ipwndfu/dfu.py`
  - USB-level DFU detection using `pyusb`
- `resources/pwn.py`
  - exploit state transitions, serial-number inspection
- `odts.py`
  - `irecovery -q` parsing for `ECID` / `BDID`
- `odtslib/device.py`
  - modernized parsing helper

### Dependencies

- `pyusb`
- vendored `libusbfinder`
- `irecovery`

### Fragile Behavior

- multiple code paths parse device state differently:
  - raw USB serial parsing through `pyusb`
  - shelling out to `irecovery -q`
- serial-number pattern matching is hardcoded
- DFU/recovery transitions depend on timing and repeated reconnects

## Stage 3: Board Configuration Lookup

### Purpose

Map the retrieved `BDID` to an Apple board/AP identifier used to locate correct firmware files inside the IPSW, such as:

- `j137ap`
- `j160ap`
- similar board config strings

### Implemented In

- original flow:
  - `odts.py` used shell `cat ... | grep ...`
- modernized helper:
  - `odtslib/device.py`
- data source:
  - `resources/device_map.txt`

### Why It Matters

The board configuration determines which exact firmware paths in the IPSW manifest correspond to the connected hardware.

### Fragile Behavior

- relies on a static text map committed into the repo
- assumes the `BDID` mapping file is complete and correct
- if the board config is wrong, every later firmware selection is wrong

## Stage 4: SHSH / Signing Ticket Retrieval

### Purpose

Request a personalized signing ticket (`.shsh2`, then moved to `resources/shsh.shsh`) using:

- `device model`
- `ECID`
- `iOS version`

This ticket is then used to wrap patched firmware images into signed IMG4 payloads.

### Implemented In

- `odts.py`
- `resources/img4.py`

### External Tool

- `resources/bin/tsschecker`

### Output

- `.shsh2` file in repo root
- moved to `resources/shsh.shsh`

### Fragile Behavior

- hard dependency on `tsschecker`
- assumes output appears in current working directory
- missing binary currently blocks this stage in the present checkout

## Stage 5: IPSW Resolution And Firmware Acquisition

There are two intended modes.

### Remote Mode

#### Purpose

Resolve the requested device/version to an IPSW and download only selected components from the remote archive.

#### Implemented In

- `iospythontools/ipswapi.py`
- `iospythontools/manifest.py`
- `resources/img4.py`

#### Dependencies

- `api.ipsw.me`
- `remotezip`
- Apple IPSW/CDN URLs returned by `ipsw.me`

#### Behavior

- lookup build ID from `ipsw.me`
- extract `BuildManifest.plist`
- selectively extract:
  - `iBSS`
  - `iBEC`
  - kernelcache
  - DeviceTree
  - trustcache
  - AOP/ISP/Callan/touch firmware for A10/A11/T2 paths

### Local Mode

#### Purpose

Use a full local IPSW supplied by the user.

#### Implemented In

- `resources/ipsw.py`
- `resources/img4.py`

#### Behavior

- unzip IPSW into `IPSW/`
- read `BuildManifest.plist`
- move needed components into `resources/StagedFiles/`

### Fragile Behavior

- remote mode depends on changing third-party services and manifest formats
- local mode historically had path and validation bugs
- manifest parsing is done mostly by string slicing rather than proper plist traversal

## Stage 6: Manifest Parsing And Firmware Path Selection

### Purpose

Given the board configuration and selected firmware version, determine exact IPSW paths for:

- `iBEC`
- `iBSS`
- `kernelcache`
- `DeviceTree`
- `trustcache`
- AOP firmware
- ISP firmware
- Callan firmware
- MultiTouch firmware
- Stockholm firmware

### Implemented In

- mostly `resources/img4.py`
- partially `iospythontools/manifest.py`

### How It Works Today

The code reads `BuildManifest.plist` as plain text and searches for markers like:

- `DeviceClass`
- `Firmware/dfu/iBEC`
- `kernelcache.release`
- `Firmware/all_flash/DeviceTree`
- `StaticTrustCache`

It then slices strings by hardcoded offsets.

### Fragile Behavior

- extremely dependent on exact XML/text layout
- not resilient to plist formatting changes
- repeated logic is copied for each firmware component

This is one of the most important areas to rewrite.

## Stage 7: Key Retrieval / KBAG Decryption

### Purpose

Obtain decryption keys for `iBSS` and `iBEC`.

### Intended Flow

1. extract KBAG information from IMG4 metadata using `img4tool -a`
2. put the device into a pwned state capable of GID decryption
3. call low-level exploit tooling to decrypt the KBAG
4. split IV and key values
5. use them to unpack `iBSS` / `iBEC`

### Implemented In

- `resources/img4.py`
- `resources/pwn.py`

### Dependencies

- `img4tool`
- vendored `ipwndfu` payloads
- `usbexec`
- DFU exploit support

### Alternate Intended Path

There is commented-out code intended to fetch keys from the iPhone Wiki first:

- `iospythontools/iphonewiki.py`

In practice, the code forces the local decryption path:

- `pwndfumodeKeys()`
- `needKeys = True`

### Fragile Behavior

- depends on exploit success
- depends on low-level payload compatibility
- relies on Python 2 legacy tooling in some paths
- the Wiki path is effectively disabled

## Stage 8: Boot Component Patching

### Purpose

Modify extracted firmware so the device will accept and boot a custom ramdisk chain.

### Main Patch Types

#### `iBSS` / `iBEC`

- decrypt IMG4 payload to raw
- patch with:
  - `kairos`
  - or `iBoot64Patcher`
- inject custom boot args
- optionally patch boot partition for dual boot on some iOS 13 flows

#### DeviceTree

- patch image type from `dtre` to `rdtr`
- optionally apply `dtree_patcher -d` for dual-boot partition handling

#### Trustcache

- patch type from `trst` to `rtsc`
- skipped for some iOS 10/11 cases

#### Kernel

- optionally patch for AMFI using:
  - `img4`
  - `Kernel64Patcher`
  - `img4tool`
- generate `kc.bpatch` diff artifact
- patch kernel type from `krnl` to `rkrn`

#### Boot Logo

- convert PNG using `ibootim`
- wrap to IMG4

### Implemented In

- `resources/img4.py`

### Dependencies

- `img4tool`
- `img4`
- `iBoot64Patcher`
- `Kernel64Patcher`
- `kairos`
- `dtree_patcher`
- `ibootim`

### Fragile Behavior

- patching assumes exact binary structure and tags
- patcher choice is hardcoded by model family
- failure handling is mostly generic `except:`

## Stage 9: Repackaging And Signing

### Purpose

Repackage patched raw firmware back into IMG4/IM4P and sign with the SHSH ticket.

### Artifacts Produced

- `ibss.patched`, `ibss.img4`
- `ibec.patched`, `ibec.img4`
- `devicetree.img4`
- `kernel.img4`
- `trustcache.img4`
- `bootlogo.img4`
- `ramdisk.img4`
- optional AOP/ISP/Callan/touch IMG4 payloads

### Implemented In

- `resources/img4.py`
- helper function `signImages()`

### Dependency

- `img4tool`

## Stage 10: Pwned DFU / Signature Bypass Setup

### Purpose

Prepare the device to accept patched images.

### Implemented In

- `resources/pwn.py`
- `resources/ipwndfu/`
- `resources/ipwndfu8012/`
- `resources/img4.py` also invokes `python2 ipwndfu8012/nop_image4.py`

### Behavior

Depending on detected CPID, the tool attempts different exploit paths:

- `iPwnder32`
- `checkm8.exploit()`
- `ipwndfu -p`
- `nop_image4.py`
- `eclipsa*`
- historically Fugu for CPID:8010

### Fragile Behavior

- many branches are hardware-specific and partially stale
- some branches refer to paths not present in this checkout
- Python 2 runtime is still required for parts of this stage
- antivirus may flag these payloads on Windows

## Stage 11: Boot Chain Execution

### Purpose

Send the staged images to the device in the correct order and instruct boot progression.

### Implemented In

- `resources/img4.py`
  - `sendImages()`

### External Tool

- `irecovery`

### Intended Sequence

1. patch out image loading checks via `nop_image4.py`
2. send `iBSS`
3. send `iBEC`
4. on some devices, send `go`
5. send `bootx`
6. send boot logo
7. send DeviceTree
8. send firmware extras on A10/A11/T2 paths
9. send trustcache if required
10. send kernel
11. final `bootx`

### Important Observation

The current code contains a blocking `input()` with the message:

- `"Stopping here as this is all we have implemented!"`

That means the boot-chain automation is explicitly incomplete in the checked-in code.

## Stage 12: Ramdisk Boot And Volume Mount

### Intended Outcome

The tool’s README claims that after the ramdisk is pushed, the device storage should mount as a volume visible in macOS / Disk Utility.

### Implemented In Code?

Not directly.

There is:

- ramdisk image generation/signing (`resources/018-75901-013.dmg` -> `ramdisk.img4`)
- boot chain sending logic

There is not:

- a clear automated mount command
- a userspace service in this repo that mounts the volume
- explicit macOS disk-attachment automation

### Likely Actual Behavior

The mounted volume step is expected to happen because the booted ramdisk environment on the target device exposes storage in a way macOS can recognize. That portion is external to the Python code in this repo.

## Pipeline Summary

The intended pipeline is:

1. parse requested device/version mode
2. ensure a DFU device is present
3. query `ECID` / `BDID`
4. map `BDID` to board config
5. obtain SHSH ticket
6. obtain BuildManifest and locate firmware paths
7. fetch or extract firmware components
8. extract KBAGs and decrypt `iBSS` / `iBEC`
9. patch boot components and optional extras
10. sign/repackage IMG4 payloads
11. exploit device into pwned image-accepting state
12. send boot chain and ramdisk
13. rely on the booted environment/macOS to expose storage

## Files By Pipeline Stage

### CLI / Orchestration

- `odts.py`

### Device Detection / Exploitation

- `resources/pwn.py`
- `resources/ipwndfu/dfu.py`
- `resources/ipwndfu/checkm8.py`
- `resources/ipwndfu8012/*`
- `resources/bin/iPwnder32`
- `resources/bin/eclipsa*`

### Firmware Resolution / Manifest Data

- `resources/ipsw.py`
- `iospythontools/ipswapi.py`
- `iospythontools/manifest.py`
- `iospythontools/iphonewiki.py`
- `resources/device_map.txt`
- `iBridge2,5.json`

### Patching / Signing / Boot Send

- `resources/img4.py`
- `resources/bin/img4tool`
- `resources/bin/img4`
- `resources/bin/iBoot64Patcher`
- `resources/bin/Kernel64Patcher`
- `resources/bin/dtree_patcher`
- `resources/bin/kairos`
- `resources/bin/ibootim`
- `resources/bin/irecovery`

### Bundled Firmware / Static Assets

- `resources/018-75901-013.dmg`
- `resources/bootlogo.png`
- `resources/StagedFiles/*`

## External Tooling And Libraries

### Python Libraries

- `requests`
- `remotezip`
- `pyusb`
- `beautifulsoup4`

### External Services

- `ipsw.me` API
- Apple IPSW/CDN URLs
- iPhone Wiki

### Bundled Native Tools

- `img4tool`
- `img4`
- `irecovery`
- `tsschecker`
- `iBoot64Patcher`
- `Kernel64Patcher`
- `dtree_patcher`
- `ibootim`
- `kairos`
- `iPwnder32`
- `eclipsa*`

### Vendored Low-Level Tooling

- `ipwndfu`
- `ipwndfu8012`

## Fragile Or Undocumented Areas

## 1. Manifest Parsing By Text Slicing

`resources/img4.py` parses `BuildManifest.plist` as text and uses hardcoded offsets. This is brittle and likely to fail on formatting differences.

## 2. Hardware-Specific Assumptions

The code hardcodes:

- specific device model families
- CPIDs
- BDID mapping expectations
- board config naming patterns
- boot patcher selection

It has little abstraction around hardware capability.

## 3. Incomplete Boot Sequence

The `sendImages()` routine contains an interactive pause indicating the implementation is incomplete.

## 4. Heavy Reliance On Subprocess Strings

Most critical operations are shell invocations with interpolated strings and minimal output validation.

## 5. Exploit Tooling As Black Boxes

Much of the critical functionality depends on vendored external exploit code. The Python glue often assumes these tools succeed without strongly validating state transitions.

## 6. Python 2 Legacy Components

Significant portions of the vendored exploit tree still require Python 2 syntax/runtime.

## 7. Missing Repo Artifacts

In the current checkout, at least these critical resources are absent:

- `resources/bin/tsschecker`
- `resources/ipwndfu8012/checkm8.py`

That means parts of the intended architecture are currently broken by missing dependencies, not just outdated logic.

## Technical Risks

## Outdated Dependencies

- root Python requirements were historically pinned to old 2019-2020 versions
- vendored exploit code is from older Python/macOS assumptions

## Deprecated macOS Behavior

- legacy logic referenced disabling Gatekeeper
- old repair flows assumed permissive `/usr/local` writes and Homebrew usage
- some bundled Mach-O tools may not behave the same on modern macOS versions

## Hardcoded URLs

- `ipsw.me`
- direct GitHub release/source URLs
- old Homebrew installer URL
- Wiki URL patterns

Any of these may change or disappear.

## Device Identifier Assumptions

- hardcoded `iBridge2,5` focus
- static CPID/BDID handling
- implicit assumptions that one board config maps cleanly to one firmware selection path

## Fragile Subprocess Interactions

- `shell=True`
- parsing `grep` output
- assuming side effects in current working directory
- weak validation of command exit statuses

## Minimal Viable Core Logic

Ignoring convenience features, credits, fix/install flows, boot logos, and experimental patch flags, the essential steps are:

1. detect a compatible device in DFU
2. retrieve enough identity information to choose correct firmware (`ECID`, `BDID`, board config)
3. obtain a valid SHSH ticket for the selected device/version
4. obtain the correct firmware files from an IPSW
5. derive decryption keys for `iBSS` and `iBEC`
6. patch `iBSS` / `iBEC` with correct boot args
7. prepare and sign at minimum:
   - `iBSS`
   - `iBEC`
   - kernel
   - DeviceTree
   - ramdisk
   - trustcache where required
8. place the device into a state that accepts patched images
9. send the boot chain in the required order with `irecovery`
10. successfully boot the ramdisk so storage becomes accessible

Everything else is secondary.

## What Is Actually Doing The Work

The tool is fundamentally a Python orchestration layer over:

- DFU exploitation
- IMG4 inspection and repackaging
- IPSW metadata lookup and selective extraction
- bootloader/kernel patchers
- `irecovery` image send commands

The Python code is not implementing the low-level exploit or patch logic itself. It is sequencing preexisting tools and intermediate files.

## Salvageable Components

These parts are conceptually salvageable:

- the overall pipeline design
- board config lookup concept
- SHSH acquisition concept
- IPSW remote/local split
- staged artifact workflow
- use of `irecovery` as the transport layer
- use of `img4tool`/patchers through well-defined wrappers

## Parts Likely No Longer Reliable

- original monolithic orchestration in old `odts.py`
- runtime setup/repair logic
- Python 2-dependent exploit paths
- shell/grep-based parsing
- partial boot send implementation in `sendImages()`
- any path that assumes missing repo resources exist

## What Must Be Rewritten

These areas need full architectural rewrite rather than incremental cleanup:

1. manifest parsing and firmware component selection
2. subprocess orchestration around bundled tools
3. state modeling for device modes and exploit status
4. boot-chain sequencing and validation
5. setup/resource management
6. separation between:
   - firmware staging
   - exploit state transitions
   - boot execution

## Suggested Modern Architecture

```text
/cli
    odts_cli.py

/core
    workflow.py
    device_detection.py
    board_config.py
    signing.py
    firmware_fetcher.py
    manifest_parser.py
    key_extraction.py
    patching_pipeline.py
    boot_chain.py
    diagnostics.py

/tools
    irecovery_wrapper.py
    img4tool_wrapper.py
    tsschecker_wrapper.py
    patcher_wrappers.py
    exploit_wrapper.py

/models
    device.py
    firmware.py
    manifest.py
    staged_artifacts.py

/resources
    ...

/docs
    AUDIT.md
    ARCHITECTURE.md
    RUNBOOK.md
```

### Recommended Responsibilities

- `device_detection.py`
  - DFU/recovery probing
  - parsing `irecovery` or USB serial info
- `board_config.py`
  - board-map loading and resolution
- `firmware_fetcher.py`
  - local vs remote IPSW access
- `manifest_parser.py`
  - proper plist parsing, not string slicing
- `key_extraction.py`
  - KBAG extraction and decryption orchestration
- `patching_pipeline.py`
  - deterministic artifact generation
- `boot_chain.py`
  - explicit send order and state validation
- `exploit_wrapper.py`
  - isolate vendored exploit tools behind a stable interface
- `diagnostics.py`
  - non-destructive dependency and environment checks

## Architecture Conclusion

ODTS is intended to be a custom tethered-boot pipeline for T2 devices, not merely an IPSW downloader or device info tool. Its essential function is to assemble a personalized, patched, signed boot chain and ramdisk, exploit the device into accepting it, and then hand off to macOS once the ramdisk environment exposes storage.

The architecture is salvageable at the workflow level, but much of the implementation is brittle glue around old low-level tools. The most valuable modernization path is to preserve the pipeline model while rewriting the orchestration, parsing, diagnostics, and tool wrappers around a small explicit core.

## Current Modernized State

The repository now has a first-party planning layer under `odtslib/` for the firmware pipeline:

- `odtslib/firmware_manifest.py`
  - structured plist parsing into dataclasses
- `odtslib/firmware_pipeline.py`
  - board-specific component lookup and artifact planning
- `odtslib/stage_model.py`
  - explicit stage metadata and result reporting
- `odtslib/tool_wrappers.py`
  - isolated binary wrappers for first-party orchestration paths

This layer is safe to use for manifest inspection, board matching, artifact planning, and non-destructive validation without invoking the low-level exploit chain.
