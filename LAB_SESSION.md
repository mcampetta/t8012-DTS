# LAB SESSION

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
