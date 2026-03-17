# LAB SESSION

## 2026-03-17 Hybrid Signing Readiness Model

### Scope

- align tool and doc messaging with the confirmed hybrid T2 design
- make SHSH failure semantics explicit as architecture-level, not just file-level

### Findings

- the current legacy T2 path uses both:
  - pwned-DFU / `nop_image4.py`
  - SHSH-backed IMG4 signing
- SHSH is not required for every single transmitted artifact
- SHSH is still functionally required overall in the current implementation
- failure to obtain SHSH for the selected device/build is therefore a real architecture blocker, not just a missing local file

### Updated Readiness Distinction

- payload readiness
- runtime readiness
- signing-material presence
- signing-status availability from Apple or an already valid existing blob
- execution readiness

### Operator/Admin Note

- an already valid previously acquired blob can satisfy the current requirement if it matches the same connected device and the same selected build

## 2026-03-17 SHSH Identity-Selection Gap

### Scope

- compare legacy `tsschecker` usage against the new safe SHSH acquisition path
- fix only missing identity-selection context for bridgeOS/T2 manifests

### Observed Failure

On the live host, the initial safe SHSH command reached `tsschecker` but failed at BuildIdentity selection for:

- device: `iBridge2,14`
- build: `19P647`
- board: `j152fap`

Observed behavior:

- firmware URL resolved correctly
- BuildManifest opened correctly
- `installType=Erase` identity selection failed
- fallback `installType=Update` also failed
- TSS request could not be built

### Gap Analysis

Legacy ODTS only passed:

- `-d`
- `-e`
- `-i`
- `-s`

The new safe path originally did the same.

The missing context was not an exploit behavior issue. It was the absence of planner-selected identity parameters that modern ODTS already knew:

- board config `j152fap`
- build ID `19P647`
- explicit repo-aligned `BuildManifest.plist`

### Fix Applied

`--acquire-shsh` now passes the richer identity-selection context when available:

- `-Z <build>`
- `-B <board_config>`
- `-m <BuildManifest.plist>`

It also now reports:

- full `tsschecker` command
- working directory
- manifest path and whether it was supplied explicitly
- temp files created during acquisition

### Validation

- `./venv/bin/python -m unittest tests.test_shsh_material tests.test_prepare_device tests.test_execution_preflight`
- `10` tests passing

## 2026-03-17 Safe SHSH Acquisition

### Scope

- convert the final current blocker into a safe operator-facing workflow
- keep SHSH acquisition separate from exploit or live execution

### Changes Applied

- added `--acquire-shsh`
- added `odtslib/shsh_material.py`
- acquisition flow now:
  - detects the connected device safely
  - reads `ECID`, product, and board context
  - selects the repo-aligned build by default unless overridden
  - invokes `tsschecker` in an isolated temp directory
  - normalizes the produced ticket to `resources/shsh.shsh`
- preflight readiness now distinguishes:
  - `payload_material_ready`
  - `signing_material_ready`

### Validation

- `./venv/bin/python -m unittest tests.test_shsh_material tests.test_prepare_device tests.test_execution_preflight tests.test_legacy_pwn_runtime`
- `12` tests passing

### Current Operator Sequence

Preferred safe sequence from a prepared host:

```bash
./venv/bin/python odts.py --prepare-device
./venv/bin/python odts.py --acquire-shsh
./venv/bin/python odts.py --preflight
```

## 2026-03-17 SHSH Material Boundary

### Scope

- isolate the final current preflight blocker at `resources/shsh.shsh`
- determine whether the missing file is payload, signing-material, or runtime related

### Findings

- payload readiness is now satisfied
- the remaining preflight blocker is signing-material readiness, not payload sourcing
- legacy ODTS obtained this file automatically during execution-oriented staging by:
  - reading connected device `ECID`
  - invoking `tsschecker`
  - producing a `.shsh2` file in the working directory
  - moving it to `resources/shsh.shsh`
- the file is treated as the signing ticket consumed by `img4tool -s`

### Current Root Cause

- removed legacy generation logic from the safe planning/preflight path
- signing-material acquisition is not yet surfaced as its own safe helper or documented operator/admin step
- the path `resources/shsh.shsh` itself is not the problem

### Current State

- payload-ready: yes
- signing-material-ready: no
- runtime-ready: no

### Next Safe Target

- add or document a non-destructive SHSH acquisition path for the connected device and selected build

## 2026-03-17 Operator Preparation Command

### Scope

- reduce operator CLI complexity for the safe planning/preflight path
- keep the flow non-destructive and hardware-safe
- orchestrate existing helpers instead of adding new execution logic

### Changes Applied

- added `--prepare-device` to `odts.py`
- the new command:
  - detects the connected device
  - reads product and board config
  - uses the repo-aligned build by default unless overridden
  - uses local `--ipsw` extraction when provided
  - otherwise uses the safe remote payload helper
  - extracts planned payloads into canonical `IPSW/`
  - runs non-destructive preflight automatically
- updated local payload extraction to persist `BuildManifest.plist` into canonical `IPSW/` as well
- added `OPERATOR_WORKFLOW.md`

### Validation

- `./venv/bin/python -m unittest tests.test_prepare_device tests.test_payload_layout tests.test_execution_preflight tests.test_legacy_pwn_runtime`
- `11` tests passing

### Current Operator Entry Point

Preferred command for a prepared lab host:

```bash
./venv/bin/python odts.py --prepare-device
```

## 2026-03-17 Host Bootstrap / Runtime Readiness

### Scope

- make lab-machine setup reproducible for additional internal hosts
- keep all work host-only and non-destructive
- clean up legacy runtime check semantics so summary labels match detailed fields

### Changes Applied

- added `scripts/bootstrap_lab_mac.sh`
- added `HOST_BOOTSTRAP.md`
- updated `odtslib/legacy_pwn_runtime.py` so fallback interpreter discovery is always recorded even when `ODTS_LEGACY_PYTHON` is set
- updated runtime-check text output to group readiness fields under a clear summary section

### Bootstrap Workflow

The new bootstrap script now:

- verifies macOS and architecture
- verifies or installs Homebrew
- verifies or installs required brew packages:
  - `pyenv`
  - `libusb`
  - `libirecovery`
  - `openssl@1.1`
  - `readline`
  - `xz`
  - `pkg-config`
- verifies or installs Python `2.7.18` via `pyenv`
- persists `ODTS_LEGACY_PYTHON` to `.odts-legacy-python.env`
- creates or updates the Python 3 `venv`
- installs Python 3 repo requirements
- installs Python 2-side `pyusb==1.0.2`
- runs:
  - `./venv/bin/python odts.py --check-legacy-pwn-runtime --json`
  - `./venv/bin/python odts.py --preflight --board-config j152fap --json`

### Current Runtime Readiness Model

Verified state from the selected Python `2.7.18` runtime:

- `interpreter_ready=true`
- `module_import_ready=false`
- `libusb_backend_ready=false`
- `vendored_libusbfinder_ready=false`

Current concrete blockers:

- `missing_pyusb`
- `missing_libusb`
- `libusbfinder_packaging_issue`

### Notes

- `Python 2.7 available` no longer depends on downstream import success
- fallback discovery results are now preserved even when `ODTS_LEGACY_PYTHON` is set explicitly
- the remaining host-side boundary is now isolated as Python 2 package/backend readiness plus vendored `libusbfinder` packaging, not interpreter absence

## 2026-03-17 10:20:56 CDT

### Scope

- Begin live lab validation on branch `modernization-audit`
- Confirm host environment, repo structure, and wrapper/tool visibility before device interaction

### Commands Run

```bash
pwd
git branch --show-current
git status --short --branch
python3 --version
rg --files
python3 odts.py --diagnostic --json
python3 odts.py setup
python3 odts.py setup --fetch-missing --dry-run
./venv/bin/python --version
./venv/bin/python odts.py --diagnostic --json
./resources/bin/irecovery -h
./resources/bin/img4tool -h
./resources/bin/img4 -h
```

### Observed Outputs

- Active branch: `modernization-audit`
- Git worktree was clean before any edits
- System `python3` is `3.13.10`
- Repo-local `./venv/bin/python` is also `3.13.10`
- `python3 odts.py --diagnostic --json` reported missing Python packages:
  - `bs4`
  - `remotezip`
- `./venv/bin/python odts.py --diagnostic --json` reported all required Python packages present
- Bundled native tools mostly appear present and callable
- `./resources/bin/irecovery -h` failed at runtime due to missing dynamic library:
  - `/usr/local/lib/libirecovery.3.dylib`

### Failures Encountered

- Category: `env`
- Failure: bundled `irecovery` is not currently runnable on this host despite diagnostics reporting `runnable=true`
- Impact: `--device-state` may misreport an environment/runtime linker issue as a device communication issue

### Fixes Applied

- Patched `odtslib/tool_wrappers.py` so version/help probes only count as runnable when the probe exits successfully
- Non-zero probe exits now surface a structured `not runnable` detail instead of a false-positive version string

### Current Working State

- Recommended interpreter for lab commands: `./venv/bin/python`
- Firmware planning and general Python diagnostics are usable through the repo-local virtualenv
- `irecovery` host runtime still needs to be validated again after the wrapper inspection fix
- No device interaction performed yet

### Additional Commands Run

```bash
./venv/bin/python -m unittest tests.test_tool_wrappers
./venv/bin/python odts.py --diagnostic --json
./resources/bin/ibootim -h
./resources/bin/iBoot64Patcher -h
./resources/bin/kairos -h
./venv/bin/python odts.py --validate-firmware --manifest resources/ipwndfu8012/BuildManifest.plist --board-config j132ap --json
```

### Additional Findings

- Tool inspection regression test passes after wrapper patch
- Updated diagnostics now classify tool probe results more accurately
- Confirmed host runtime blockers:
  - `irecovery` fails to load `/usr/local/lib/libirecovery.3.dylib`
  - `ibootim` fails to load `/usr/local/lib/libpng16.16.dylib`
- Confirmed non-blocking non-zero help exits:
  - `iBoot64Patcher`
  - `kairos`
  - `iPwnder32`
- Non-destructive firmware validation succeeded for bundled manifest:
  - board config `j132ap`
  - build `19P647`
  - 6 planned staged components

### Current Root Cause Categories

- `env`: bundled `irecovery` is not runnable due to missing host dynamic library
- `env`: bundled `ibootim` is not runnable due to missing host dynamic library
- `parsing`: no current parsing failure observed
- `wrapper`: diagnostics false-positive fixed in first-party wrapper inspection

### Current Working State

- Safe first-party firmware planning path is working
- Wrapper-layer diagnostics are now trustworthy for distinguishing executable vs loader-failure cases
- Live `--device-state` is currently expected to fail in the `env` category until `irecovery` linkage is resolved or an alternate callable `irecovery` path is intentionally adopted

## 2026-03-17 Binary Resolution Update

### Scope

- Prefer runnable system/Homebrew binaries over stale bundled copies
- Classify probe failures by cause
- Surface candidate selection details in operator-facing output

### Changes Applied

- Updated `odtslib/tool_wrappers.py`:
  - candidate paths are now checked in priority order
  - each candidate must pass an execution probe
  - candidate status is classified as:
    - `missing_binary`
    - `not_executable`
    - `loader_failure`
    - `bad_exit_code`
    - `runnable`
  - first runnable candidate is selected
  - selected path and rejection reasons are preserved in inspection output
- Updated `odtslib/device_state.py`:
  - verbose output now shows all `irecovery` candidates considered
  - each candidate includes path, status, and acceptance/rejection reason
  - selected `irecovery` path is reported explicitly
- Updated `odts.py` diagnostic text output to include selected candidate details
- Added wrapper tests covering:
  - dyld loader failure classification
  - fallback from broken bundled binary to runnable system binary
  - non-executable candidate classification
  - acceptance of non-zero help/usage probes when the process is still clearly runnable

### Commands Run

```bash
/opt/homebrew/bin/irecovery -h
./venv/bin/python -m unittest tests.test_tool_wrappers
./venv/bin/python odts.py --device-state --verbose
./venv/bin/python odts.py --device-state --json
```

### Observed Outputs

- `/opt/homebrew/bin/irecovery` is healthy and runnable on this host
- `resources/bin/irecovery` fails probe with a dyld loader error for `/usr/local/lib/libirecovery.3.dylib`
- `./venv/bin/python odts.py --device-state --verbose` selected `/opt/homebrew/bin/irecovery`
- Candidate breakdown from the live device-state flow:
  - `system`: `runnable`
  - `bundled`: `loader_failure`
- Current device-state result:
  - `tool_comm_failure`
  - `irecovery -q` returned `ERROR: Unable to connect to device`

### Root Cause Category

- `wrapper`: fixed binary selection and false-positive inspection behavior
- `env`: bundled repo `irecovery` remains stale and not host-runnable
- `device-state`: current non-destructive query reached the selected system binary but could not connect to a device in the tested state

### Current Working State

- `irecovery` resolution now prefers `/opt/homebrew/bin/irecovery` over the broken bundled copy
- Device-state diagnostics now distinguish binary-selection issues from actual device communication failures

## 2026-03-17 Live Device-State Success

### Scope

- Validate real hardware device-state detection on the connected T2 target
- Confirm hardware identity can be carried into non-destructive firmware planning

### Observed Result

- Device state: `identifiers_ready`
- Selected `irecovery`: `/opt/homebrew/bin/irecovery`
- CPID: `0x8012`
- BDID: `0x3a`
- ECID: parsed successfully
- PRODUCT: `iBridge2,14`
- MODEL: `j152fap`
- MODE: `Recovery`

### Validation Outcome

- Confirms the wrapper-resolution fix worked on real hardware
- Confirms the system/Homebrew `irecovery` path is usable for live detection
- Confirms the connected hardware identity is T8012 / board `0x3A` / model `j152fap`

### Additional Commands Run

```bash
./venv/bin/python odts.py --validate-firmware --manifest resources/ipwndfu8012/BuildManifest.plist --board-config j152fap --json
```

### Firmware Planning Result

- Non-destructive planning succeeded for `j152fap`
- Selected manifest identity:
  - `chip_id`: `0x8012`
  - `board_id`: `0x3A`
  - `device_class`: `j152fap`
  - `variant`: `Customer Erase Install (IPSW)`
- Planned 7 component artifacts:
  - `ibec`
  - `ibss`
  - `kernelcache`
  - `devicetree`
  - `trustcache`
  - `aopfw`
  - `touch`

### Identity Match Assessment

- Live hardware CPID `0x8012` matches planned `chip_id` `0x8012`
- Live hardware BDID `0x3a` matches planned `board_id` `0x3A`
- Live hardware MODEL `j152fap` matches planned `device_class` `j152fap`
- The generated artifact plan matches the connected hardware identity

### Fixes Applied

- Corrected `identifiers_ready` failure-cause formatting so `none` renders as a single value instead of character-by-character output

### Current Working State

- Device-state detection is validated on real hardware
- Firmware planning for `j152fap` is validated and identity-aligned
- No destructive or device-altering actions were taken in this pass

## 2026-03-17 Planning / Preflight Boundary

### Scope

- Add a non-destructive execution graph for the connected device
- Add a non-destructive preflight mode to separate planning confidence from live execution readiness

### Changes Applied

- Added CLI modes:
  - `--execution-graph`
  - `--preflight`
- Added `odtslib/execution_preflight.py`
- Added structured connected-device reuse for planning via `collect_device_state_report()`
- Added tests for:
  - connected-device board selection during graph generation
  - preflight blocker detection
- Added `EXECUTION_PREFLIGHT.md`

### Commands Run

```bash
./venv/bin/python odts.py --execution-graph
./venv/bin/python odts.py --execution-graph --json
./venv/bin/python odts.py --preflight
./venv/bin/python odts.py --preflight --json
./venv/bin/python -m unittest tests.test_tool_wrappers tests.test_device_state tests.test_firmware_pipeline tests.test_execution_preflight
```

### Observed Outputs

- `--execution-graph` resolved the connected device as `j152fap`
- The graph listed:

## 2026-03-17 Payload Sourcing Boundary Cleared

### Scope

- Confirm that payload sourcing is no longer the current blocker
- Add a safe remote IPSW helper for future lab sessions
- Keep all work non-destructive and hardware-independent

### Changes Applied

- Added `odtslib/remote_ipsw.py`
- Added CLI mode:
  - `--remote-payload-layout DEVICE`
- Added optional build override:
  - `--build BUILD`
- Added remote helper cache file:
  - `IPSW/.odts-remote-payload-cache.json`
- Added tests covering:
  - metadata selection and build override
  - remote inspection fallback behavior
  - selective extraction planning
  - cache-file recording
- Updated operator docs:
  - `REMOTE_IPSW_SOURCING.md`
  - `EXECUTION_PREFLIGHT.md`
  - `LIVE_READINESS.md`

### Commands Run

```bash
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --json
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --extract-planned-payloads --payload-root /tmp/odts-remote-livecheck.LpvQku --json
./venv/bin/python odts.py --preflight --json
cat IPSW/.odts-remote-payload-cache.json
./venv/bin/python -m unittest tests.test_remote_ipsw tests.test_payload_layout tests.test_execution_preflight tests.test_tool_wrappers tests.test_device_state tests.test_firmware_pipeline
```

### Observed Outputs

- Remote metadata source used:
  - `https://api.ipsw.me/v4/device/iBridge2,14?type=ipsw`
- Remote restore URL resolved successfully for the current planning build `19P647`
- Range-based remote ZIP inspection succeeded
- Planned `j152fap` payload paths were present in the remote archive
- Remote helper wrote:
  - `IPSW/.odts-remote-payload-cache.json`
- Current cache contents include:
  - product identifier
  - selected build
  - selected version
  - resolved restore URL
  - board config
  - extracted payload list
- `./venv/bin/python odts.py --preflight --json` now reports:
  - `blockers: []`
  - `ready_for_live_execution: true`
  - readiness level still `ready for planning only`
  - remaining reason: first execution-side step `enter-pwned-dfu` is still `unverified`

### Root Cause Classification

- `payload sourcing`: resolved
- `wrapper`: resolved for `irecovery`
- `execution-side`: still unverified at the first live step boundary

### Current Working State

- Local IPSW sourcing path is validated
- Remote IPSW sourcing helper is implemented and safely inspectable
- Preflight can now pass with no payload blockers
- Remaining uncertainty is execution-side only
  - selected board identity
  - component source paths
  - staged outputs
  - planned patch/sign/send steps
  - tool assignment per step
  - `validated` / `legacy` / `unverified` status per step
- `--preflight` confirmed tool readiness for the planned flow:
  - `irecovery` selected from `/opt/homebrew/bin/irecovery`
  - required bundled patch/sign tools are runnable
- `--preflight` reported current blockers as unresolved local firmware source payloads for:
  - `ibec`
  - `ibss`
  - `kernelcache`
  - `devicetree`
  - `trustcache`
  - `aopfw`
  - `touch`

### Current Remaining Blockers

- Category: `parsing/artifact-resolution`
- Manifest planning is correct, but the required firmware payload files are not yet present at any expected local source location checked by preflight

### Current Working State

- Safe planning boundary is stronger and explicit
- Live execution readiness can now be assessed without invoking execution-side code
- Remaining blockers are now concrete and reproducible

## 2026-03-17 Live Readiness Classification

### Scope

- Derive an explicit lab readiness level from the connected-device execution graph and preflight results
- Identify the first execution-side step after planning without executing it

### Observed Result

- Current readiness level: `ready for planning only`
- First execution-side step after planning: `enter-pwned-dfu`
- First execution-side module: `resources/pwn.py`
- First execution-side tool/entry: `ipwndfu8012/nop_image4.py`
- First execution-side classification: `unverified`

### Reasoning

- Planning and preflight are validated and reproducible
- The required external tools for the planned flow are currently runnable
- The repo is still blocked on unresolved local source payloads for the planned `j152fap` artifacts
- The first execution-side entry point remains legacy/unverified in this lab session

### Current Remaining Blockers

- `ibec`: planned source unresolved
- `ibss`: planned source unresolved
- `kernelcache`: planned source unresolved
- `devicetree`: planned source unresolved
- `trustcache`: planned source unresolved
- `aopfw`: planned source unresolved
- `touch`: planned source unresolved

### Outputs Added

- `LIVE_READINESS.md`

### Current Working State

- The repo is not yet ready for a first controlled live execution-side step
- The next safe action is still to resolve the planned firmware payload sources and rerun preflight

## 2026-03-17 Missing Payload Contract Analysis

### Scope

- Turn unresolved preflight payload blockers into an explicit, traceable contract
- Improve operator-facing preflight output for unresolved payloads

### Observed Host State

- `IPSW/` is absent in this checkout
- `resources/Firmware/` is absent in this checkout

### Blocker Analysis

- Primary issue: `missing local files`
- Secondary issue: `stale legacy assumptions`
- Contract issue:
  - planning currently probes several possible firmware roots
  - legacy execution-side code still implies older repo-local extracted paths
  - there is no single canonical extracted-firmware root yet

### Changes Applied

- Added unresolved-payload analysis to `--preflight`
- Added `MISSING_PAYLOADS.md` with per-component traceability and proposed fixes

### Proposed Smallest Non-Destructive Fixes

- `ibec`:
  - extract selected IPSW payload into a canonical local extracted-firmware root
  - normalize legacy fallback probing away from `resources/Firmware/Firmware/...`
- `ibss`:
  - same as `ibec`
- `kernelcache`:
  - resolve from the canonical extracted IPSW root
  - keep the top-level payload-path exception explicit in planning/preflight
- `devicetree`:
  - same canonical extracted-root fix as `ibec`
- `trustcache`:
  - same canonical extracted-root fix as `ibec`
- `aopfw`:
  - same canonical extracted-root fix as `ibec`
- `touch`:
  - same canonical extracted-root fix as `ibec`

### Current Working State

- Preflight blockers are now explicit and traceable per payload
- The next safe engineering step is path normalization and source-resolution contract cleanup, not live execution

## 2026-03-17 Payload Layout Helper

### Scope

- Add a non-destructive helper to inspect or prepare the expected local payload layout from a local IPSW

### Changes Applied

- Added `--payload-layout`
- Added `--extract-planned-payloads`
- Added payload layout inspection/extraction support in `odtslib/payload_layout.py`
- Updated preflight readiness output to state:
  - whether the only blocker is missing payload material
  - what exact operator action is needed
  - whether valid local payloads alone would enable controlled live step testing

### Current Conclusion

- The current hard blocker is missing local payload material
- The smallest non-destructive operator action is:
  - supply a valid local IPSW for the selected target
  - inspect it with `--payload-layout`
  - extract the planned payloads into the canonical local payload root
  - rerun `--preflight`
- A valid local IPSW/extraction is sufficient to clear the current payload blocker
- A valid local IPSW/extraction is not, by itself, sufficient to move the repo to `ready for controlled live step testing`

## 2026-03-17 Legacy IPSW Sourcing Audit

### Findings

- Remote legacy flow used `ipsw.me` metadata plus `RemoteZip` extraction from the Apple restore URL
- Local legacy flow extracted a full IPSW archive into `IPSW/`
- Legacy execution then moved required payloads from `IPSW/` into `resources/StagedFiles/`
- The bundled manifest was never sufficient by itself for live staging; payload files were still expected from remote extraction or a local IPSW tree

### Output Added

- `IPSW_SOURCING.md`

### Current Working State

- The current repo state is consistent with a missing local IPSW/extracted payload tree
- The next operator step is to validate and, if appropriate, extract the planned payloads from a local IPSW into `IPSW/`

## 2026-03-17 Remote IPSW Helper Validation

### Scope

- Add a safe remote metadata and archive-inspection helper
- Keep payload sourcing non-destructive and hardware-independent
- Record repeatable remote URL and payload-source state for future lab sessions

### Commands Run

```bash
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --json
./venv/bin/python odts.py --preflight --json
cat IPSW/.odts-remote-payload-cache.json
./venv/bin/python -m unittest tests.test_remote_ipsw tests.test_payload_layout tests.test_execution_preflight tests.test_tool_wrappers tests.test_device_state tests.test_firmware_pipeline
```

### Observed Outputs

- Remote metadata lookup succeeded via:
  - `https://api.ipsw.me/v4/device/iBridge2,14?type=ipsw`
- Remote restore URL resolved successfully
- Range-based remote ZIP inspection succeeded
- Planned `j152fap` payload files were present in the remote archive
- Selective remote extraction succeeded into a throwaway payload root:
  - `BuildManifest.plist`
  - `Firmware/dfu/iBEC.j152f.RELEASE.im4p`
  - `Firmware/dfu/iBSS.j152f.RELEASE.im4p`
  - `kernelcache.release.ibridge2p`
  - `Firmware/all_flash/DeviceTree.j152fap.im4p`
  - `Firmware/018-77781-055.dmg.trustcache`
  - `Firmware/AOP/aopfw-t8012aop.im4p`
  - `Firmware/J152f_Multitouch.im4p`
- Cache file written:
  - `IPSW/.odts-remote-payload-cache.json`
- Current cache records:
  - product identifier
  - build
  - version
  - resolved restore URL
  - board config
  - extracted payload list
- Current `--preflight --json` result:
  - `blockers: []`
  - readiness level: `ready for planning only`
  - remaining uncertainty: first execution-side step `enter-pwned-dfu` is still `unverified`

### Changes Applied

- Added `odtslib/remote_ipsw.py`
- Added CLI support:
  - `--remote-payload-layout DEVICE`
  - `--build BUILD`
- Added remote helper cache file support
- Added `REMOTE_IPSW_SOURCING.md`
- Updated:
  - `EXECUTION_PREFLIGHT.md`
  - `LIVE_READINESS.md`

### Current Working State

- Local and remote payload sourcing paths are now both available
- Payload sourcing is no longer the active blocker on this machine
- Remaining unknown is execution-side only

## 2026-03-17 Enter Pwned DFU Preview

### Scope

- Instrument the first execution-side step for observability only
- Do not execute the exploit path
- Capture the real launcher, interpreter, and file-dependency contract

### Commands Run

```bash
./venv/bin/python odts.py --preview-enter-pwned-dfu
./venv/bin/python odts.py --preview-enter-pwned-dfu --json
./venv/bin/python -m unittest tests.test_pwn_preview tests.test_remote_ipsw tests.test_payload_layout tests.test_execution_preflight
```

### Observed Outputs

- Preview call path for the current T8012 branch:
  - `resources.pwn.pwndfumode()`
  - `resources/ipwndfu8012/ipwndfu -p`
  - re-acquire DFU device and inspect for `PWND:[checkm8]`
  - `python resources/ipwndfu8012/nop_image4.py`
- Preview verified referenced files exist
- Safe launcher probe result for `resources/ipwndfu8012/ipwndfu`:
  - `missing_interpreter`
  - `script shebang requires missing interpreter /usr/bin/python`
- `resources/pwn.py` currently invokes `nop_image4.py` through bare `python`
- Host interpreter result:
  - `python`: absent
  - `python2`: absent
  - `python2.7`: absent
- Static compatibility analysis found Python 2 markers in:
  - `resources/ipwndfu8012/ipwndfu`
  - `resources/ipwndfu8012/dfu.py`
  - `resources/ipwndfu8012/usbexec.py`

### Changes Applied

- Added `--preview-enter-pwned-dfu`
- Added `odtslib/pwn_preview.py`
- Added `ENTER_PWNED_DFU_ANALYSIS.md`
- Added preview regression tests in `tests/test_pwn_preview.py`

### Current Boundary

- `enter-pwned-dfu` remains `unverified`
- preflight payload and tool blockers are cleared
- the current blocker is execution-environment compatibility and live-step observability

### Exact Stop Conditions For Any Future Controlled Test

- do not proceed while `/usr/bin/python` is still missing for the `ipwndfu8012` shebang path
- do not proceed while bare `python` is still missing for the `nop_image4.py` launch path
- do not proceed while the transitive helper chain still requires unresolved Python 2 compatibility
- stop immediately on any unexpected device disconnect or unplanned mode transition
- stop immediately if observed output diverges from the previewed first-step expectations

## 2026-03-17 Enter Pwned DFU Runtime Audit

### Scope

- Expand the preview into a full static runtime compatibility audit
- Trace the local import chain behind `ipwndfu -p` and `nop_image4.py`
- Keep the work fully non-destructive and hardware-independent

### Commands Run

```bash
./venv/bin/python odts.py --audit-enter-pwned-dfu-runtime
./venv/bin/python odts.py --audit-enter-pwned-dfu-runtime --json
./venv/bin/python -m unittest tests.test_pwn_runtime_audit tests.test_pwn_preview tests.test_remote_ipsw tests.test_payload_layout tests.test_execution_preflight tests.test_tool_wrappers tests.test_device_state tests.test_firmware_pipeline
```

### Observed Outputs

- Static runtime audit confirmed entry points:
  - `resources/ipwndfu8012/ipwndfu -p`
  - `python resources/ipwndfu8012/nop_image4.py`
- Local imported-file chain includes:
  - `dfu.py`
  - `usbexec.py`
  - `checkm8.py`
  - `dfuexec.py`
  - `libusbfinder/__init__.py`
  - vendored `usb/...` modules
- Current blocker chain is:
  - `interpreter_missing`
  - `path_assumption`
  - `python2_syntax_dependency`
  - `macOS runtime assumption`
- Current conclusion:
  - the remaining issue is primarily runtime compatibility, not current device behavior
  - device behavior is still unknown, but the chain does not currently reach that boundary on this host

### Changes Applied

- Added `--audit-enter-pwned-dfu-runtime`
- Added `odtslib/pwn_runtime_audit.py`
- Added `PWN_RUNTIME_AUDIT.md`
- Added `tests/test_pwn_runtime_audit.py`

### What Would Still Remain Unknown If Runtime Blockers Were Solved

- actual exploit behavior on the connected device
- whether `PWND:[checkm8]` appears after the exploit launch
- whether USB re-enumeration timing matches the legacy sleep-and-reacquire assumption
- whether `nop_image4.py` succeeds after a real pwned DFU transition
- whether later live execution-side boot/send steps behave as planned

## 2026-03-17 Enter Pwned DFU Remediation Triage

### Scope

- Convert the runtime audit into a safe modernization triage plan
- Identify the smallest change slice that could move the chain from runtime-blocked to preview-clean
- Avoid broad rewrites and avoid any live execution changes

### Changes Applied

- Added `ENTER_PWNED_DFU_REMEDIATION_PLAN.md`
- Updated `LIVE_READINESS.md`

### Current Triage Result

- host shim only:
  - `resources/ipwndfu8012/ipwndfu`
  - `resources/pwn.py`
- low-risk Python 3 port candidate:
  - `resources/ipwndfu8012/utilities.py`
- moderate-risk port candidates:
  - `resources/ipwndfu8012/dfu.py`
  - `resources/ipwndfu8012/alloc8.py`
  - `resources/ipwndfu8012/recovery.py`
- high-risk behavior-sensitive files:
  - `resources/ipwndfu8012/usbexec.py`
  - `resources/ipwndfu8012/checkm8.py`
  - `resources/ipwndfu8012/dfuexec.py`
  - `resources/ipwndfu8012/limera1n.py`
  - `resources/ipwndfu8012/SHAtter.py`
  - `resources/ipwndfu8012/steaks4uce.py`
- external dependency packaging issue:
  - `resources/ipwndfu8012/libusbfinder/__init__.py`

### Recommended Order Of Operations

1. define the interpreter contract explicitly
2. remove implicit `/usr/bin/python` and bare `python` launcher assumptions
3. separate libusb packaging from exploit behavior
4. only then consider a tightly scoped transitive compatibility pass
5. re-run preview and runtime audit before any live-step discussion

### Current Working State

- the active blocker remains runtime compatibility
- the next engineering step is a narrow runtime-contract decision, not exploit restoration
- even after runtime remediation, device behavior would still remain unverified

## 2026-03-17 Legacy Runtime Contract Cleanup

### Scope

- implement the smallest safe host-shim/runtime-contract cleanup
- remove implicit interpreter assumptions
- keep high-risk legacy behavior files untouched

### Changes Applied

- Added `odtslib/legacy_pwn_runtime.py`
- Added `LEGACY_PWN_RUNTIME_CONTRACT.md`
- Updated `resources/pwn.py` so the T8012 path uses an explicit legacy interpreter launcher
- Updated `resources/ipwndfu8012/ipwndfu` shebang from `/usr/bin/python` to `/usr/bin/env python2`
- Updated preview and runtime-audit output to report:
  - selected interpreter
  - libusb packaging status
  - `Preview-Clean Runtime Boundary`

### Commands Run

```bash
./venv/bin/python odts.py --preview-enter-pwned-dfu
./venv/bin/python odts.py --audit-enter-pwned-dfu-runtime
./venv/bin/python -m unittest tests.test_pwn_preview tests.test_pwn_runtime_audit tests.test_remote_ipsw tests.test_payload_layout tests.test_execution_preflight tests.test_tool_wrappers tests.test_device_state tests.test_firmware_pipeline
```

### Observed Outputs

- Preview now reports explicit launch placeholders instead of implicit `/usr/bin/python` or bare `python`
- Current interpreter contract:
  - env var: `ODTS_LEGACY_PYTHON`
  - fallback discovery: `python2.7`, `python2`
  - current selected interpreter: none
- Current dependency packaging result:
  - `pyusb_available=True`
  - `pyusb_libusb_backend_available=True`
  - `host_supported_by_vendored_libusbfinder=False`
- Current runtime boundary result:
  - `Preview-Clean Runtime Boundary: False`

### Current Working State

- implicit interpreter assumptions have been removed from the ODTS T8012 launch path
- the active blocker is now explicit:
  - no selected legacy Python 2 interpreter
  - unresolved vendored libusb packaging assumptions on this host
- high-risk Python 2 behavior files remain untouched

## 2026-03-17 Legacy Runtime Host Check

### Scope

- add a host-only runtime check command for the declared legacy T8012 contract
- report exact interpreter, import, and libusb packaging state
- provide an explicit export hint for operators

### Changes Applied

- added `--check-legacy-pwn-runtime`
- added `LEGACY_PWN_RUNTIME_SETUP.md`
- updated `LEGACY_PWN_RUNTIME_CONTRACT.md`
- updated `LIVE_READINESS.md`

### Commands Run

```bash
./venv/bin/python odts.py --check-legacy-pwn-runtime
./venv/bin/python odts.py --check-legacy-pwn-runtime --json
./venv/bin/python -m unittest tests.test_legacy_pwn_runtime tests.test_pwn_preview tests.test_pwn_runtime_audit
```

### Observed Outputs

- current host-side result:
  - `Preview-Clean Runtime Boundary: False`
  - `missing_python2`
  - `libusbfinder_packaging_issue`
- runtime status fields now reported separately:
  - `interpreter_ready`
  - `module_import_ready`
  - `libusb_backend_ready`
  - `vendored_libusbfinder_ready`
  - `preview_clean_runtime_boundary`
- current import checks:
  - `usb=True`
  - `usb.backend.libusb1=True`
- current export hint:
  - `export ODTS_LEGACY_PYTHON=/absolute/path/to/python2.7`

### Current Working State

- the runtime boundary is now explicit and host-checkable
- the next host-only step is to provide an explicit Python 2.7 interpreter path
- even after that, vendored libusbfinder packaging may still remain the active unresolved host-side issue

## 2026-03-17: SHSH Fallback Strategy

### Goal

- make SHSH acquisition try the repo-aligned build first for compatibility
- fall back to the latest signed build only if Apple rejects the repo-aligned build
- always normalize the resulting blob to `resources/shsh.shsh`
- record which build was actually used

### Changes Applied

- updated `odtslib/shsh_material.py`
  - default acquisition strategy is now `repo-aligned then latest signed`
  - report now records `attempted_builds`, `fallback_used`, `used_build`, and `used_latest_signed`
- updated `tests/test_shsh_material.py`
- updated `tests/test_execution_preflight.py`

### Commands Run

```bash
./venv/bin/python -m unittest tests.test_shsh_material tests.test_execution_preflight
./venv/bin/python odts.py --acquire-shsh --json
./venv/bin/python odts.py --acquire-shsh
```

### Observed Outputs

- repo-aligned build `19P647` was attempted first and rejected by Apple for `iBridge2,14`
- acquisition then fell back automatically to latest signed build `23P3120`
- normalized signing material was written to `resources/shsh.shsh`
- host-only compatibility probe succeeded:
  - `im4m_generation_succeeded=True`
  - `available_artifacts_wrapped_successfully=7`
  - `available_artifacts_rejected=0`
  - `host_side_mismatch_rejected=False`

### Current Working State

- default SHSH acquisition is now compatibility-first with automatic signed-build fallback
- the report clearly records both the attempted repo-aligned build and the final build used
- current normalized signing material for this lab device was acquired from signed build `23P3120`
