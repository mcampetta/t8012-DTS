# ODTS Audit

## Repository Overview

- Purpose: ODTS is a tethered boot / ramdisk staging tool for checkm8-vulnerable T2 (`T8012`) devices, intended to mount internal storage for transfer or recovery workflows.
- Primary architecture: one monolithic CLI entrypoint (`odts.py`) orchestrates first-party helper modules under `resources/` and `iospythontools/`, plus a large vendored payload of exploit code, Mach-O utilities, firmware blobs, and staged artifacts.
- Current state before modernization:
  - single-file control flow with many implicit side effects
  - runtime dependency installation and host modification logic
  - frequent shell invocation with `shell=True`
  - mixed Python 3 and Python 2 code in the same repository
  - minimal structured error reporting

## Entry Points

- `odts.py`
  - main user-facing CLI
  - supports remote IPSW fetch flow, local IPSW flow, pwn-only mode, and legacy repair mode
- `resources/pwn.py`
  - first-party wrapper around vendored exploit payloads and bundled binaries
- `resources/img4.py`
  - first-party staging/signing/sending logic for IMG4 assets
- Vendored legacy executables/scripts
  - `resources/ipwndfu/`
  - `resources/ipwndfu8012/`
  - `resources/bin/*`

## Current Execution Flow

1. Parse CLI flags.
2. Clear a list of staged artifacts in `resources/StagedFiles`.
3. For remote IPSW mode:
   - query device state via `irecovery -q`
   - derive board config from `resources/device_map.txt`
   - request SHSH via `tsschecker`
   - download BuildManifest and other firmware assets via `ipsw.me` and remote zip extraction
   - call vendored exploit path to enter pwned DFU
   - patch/sign boot files with bundled binaries
   - send images via `irecovery`
4. For local IPSW mode:
   - unzip full IPSW into `IPSW/`
   - validate BuildManifest
   - stage/sign/send assets using the same helper layer
5. For pwn-only mode:
   - run exploit helper only

## External Dependencies

### Python Packages

- `requests`
- `remotezip`
- `pyusb`
- `beautifulsoup4`

### Bundled Native Tools

- `img4tool`
- `img4`
- `irecovery`
- `tsschecker`
- `iBoot64Patcher`
- `Kernel64Patcher`
- `dtree_patcher`
- `ibootim`
- `iPwnder32`
- `eclipsa*`

### Vendored Code

- `resources/ipwndfu/`
- `resources/ipwndfu8012/`
- duplicated `iospythontools` trees at repo root and under `resources/`

## Bundled Resources

- Ramdisk image: `resources/018-75901-013.dmg`
- boot logo: `resources/bootlogo.png`
- sample/staged firmware artifacts in `resources/StagedFiles/`
- device map: `resources/device_map.txt`
- local ipsw.me cache file: `iBridge2,5.json`
- multiple `.pyc` files and `__pycache__` directories committed to source control

## Network / Download Dependencies

- `https://api.ipsw.me/` for build/version lookup
- IPSW URLs returned by `ipsw.me`, extracted remotely via `remotezip`
- `https://www.theiphonewiki.com/` for keys lookup code
- Legacy repair paths referenced:
  - GitHub release zip for `img4tool`
  - GitHub source zip for `libirecovery`
  - Homebrew installer script
  - Fugu release zip

## macOS-Specific Assumptions

- hard gate on `platform.system() == "Darwin"` for operational flows
- expects Mach-O binaries under `resources/bin/`
- assumes `irecovery` interaction with a locally attached Apple device in DFU/recovery mode
- legacy code modifies `/usr/local/*`
- legacy code referenced `spctl --master-disable`
- legacy repair path assumed Homebrew and autotools/make toolchain on macOS

## Python Version Assumptions

- top-level code targets Python 3
- large vendored sections still require Python 2 syntax and semantics
- some runtime paths directly call `python2`, `python2.7`, or Python 2 scripts

## Likely Breakpoints On A Modern System

- runtime self-install and `pip install -r requirements.txt` on startup
- deprecated or unsafe host modification behavior (`spctl`, `/usr/local`, `sudo make install`)
- missing Python 2 runtime for vendored exploit scripts
- invalid or incomplete command paths:
  - references to `resources/ipwndfuX` and `resources/ipwndfuKeys`, which do not exist in this checkout
- brittle `shell=True` usage and command parsing
- local IPSW flow bugs in the original CLI
- partial / unfinished boot flow in `resources/img4.py` (`input()` pause mid-send)
- Windows Defender / AV flagging bundled hacktool binaries
- committed `venv/`, `.pyc`, and generated artifacts polluting the tree

## Outdated Components

- `requirements.txt` pinned to 2019-2020 era versions plus lint tooling as runtime deps
- Python 2 vendored scripts under `resources/ipwndfu8012/` and `resources/ipwndfu/`
- hardcoded URLs using old GitHub/Homebrew assumptions
- duplicated helper modules under both `iospythontools/` and `resources/iospythontools/`
- ad hoc plist parsing by string slicing in `resources/img4.py`

## Risky Patterns

- blanket `except:` in many critical paths
- runtime package installation
- runtime download/install of external tools
- shell invocation with interpolated strings
- recursive self-restart via `os.execl` inside helper code
- direct host modification under `/usr/local`
- implicit `os.chdir()` across modules
- interactive `input()` pauses in operational code

## Dead Code Or Unclear Code Paths

- large commented blocks in `resources/img4.py`
- duplicated `iospythontools` package trees with unclear authority
- legacy `--fix` flow attempted to repair host tools but is no longer safe to preserve
- some exploit support branches reference missing directories and appear non-functional in this checkout

## Dependency / Version Drift

- root requirements mixed dev tools and runtime deps
- vendored exploit code predates current Python packaging/runtime norms
- repo assumes an older macOS toolchain layout and permissive security posture
- device support logic is tightly bound to specific historical firmware/build assumptions

## Modernization Recommendations

1. Keep exploit internals vendored but isolate them behind a modern Python 3 CLI layer.
2. Remove all runtime self-install and host-modification behavior.
3. Add a real diagnostic / dry-run mode before any device actions.
4. Centralize paths/constants and make failures explicit.
5. Convert first-party helper code to Python 3 and stop using interactive repair prompts.
6. Replace shell-string subprocess usage in first-party code where practical.
7. Keep legacy Python 2 payloads documented and quarantined until they can be ported safely on a Mac.
8. Add minimal tests around safe helper logic only.

## Prioritized Remediation Plan

### P0

- preserve the original state with a local git tag
- replace unsafe startup/install behavior
- add diagnostics and dry-run support
- fix broken top-level local/remote execution paths

### P1

- clean requirements and repo hygiene
- add structured logging and documentation
- isolate or deprecate unsafe repair logic

### P2

- on macOS, validate actual device workflows and decide whether vendored Python 2 exploit paths should be ported or wrapped
- rationalize duplicated helper packages
- split `resources/img4.py` into smaller testable units after hardware validation

## Snapshot Notes

- Original commit at audit start: `7ba2380613e39929ef5e5a97ca5bb1bf0a66935d`
- Local recovery tag created: `legacy-original`
- Remote tag push failed with GitHub `403` against `origin`, so off-machine preservation still requires authenticated manual push

