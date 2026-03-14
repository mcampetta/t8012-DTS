# Module Boundaries

This document defines the current responsibility boundaries for the repository after the recent refactoring work. It is intentionally strict: it distinguishes safe planning code from live execution code, and it does not assume that unverified hardware/macOS paths work.

## 1. Safe First-Party Structured Modules

These modules are the current maintainable core. They are first-party, structured, and intended to be safe for developer use.

## `odtslib/firmware_manifest.py`

- Purpose:
  - Parse `BuildManifest.plist` using `plistlib`
  - Convert manifest contents into structured dataclasses
  - Expose `FirmwareManifest`, `BuildIdentity`, and `ManifestComponent`
- Inputs:
  - path to a `BuildManifest.plist`
- Outputs:
  - structured manifest model
- Side effects:
  - none
- External dependencies:
  - Python stdlib `plistlib`
- Validation status:
  - covered by tests
  - non-destructive
- Rewrite priority:
  - low
- Solves:
  - replaces brittle text-sliced manifest parsing
- Covered by tests:
  - yes, in `tests/test_firmware_pipeline.py`
- Non-destructive:
  - yes
- Dependents:
  - `odtslib/firmware_pipeline.py`
  - `resources/img4.py`
  - `odts.py` via `--validate-firmware`

## `odtslib/firmware_pipeline.py`

- Purpose:
  - Select a board-specific `BuildIdentity`
  - Resolve board-specific firmware components
  - Build an artifact plan for staged outputs
  - Describe stage results and tool-invocation planning
- Inputs:
  - `FirmwareManifest`
  - `board_config`
- Outputs:
  - `FirmwareArtifactPlan`
  - stage result records
  - JSON-serializable planning report
- Side effects:
  - none
- External dependencies:
  - `odtslib/firmware_manifest.py`
  - `odtslib/stage_model.py`
- Validation status:
  - covered by tests
  - non-destructive
- Rewrite priority:
  - low to medium
- Solves:
  - separates manifest loading, identity selection, and artifact planning from execution
- Covered by tests:
  - yes
- Non-destructive:
  - yes
- Dependents:
  - `odts.py`
  - `resources/img4.py`

## `odtslib/stage_model.py`

- Purpose:
  - Define stage metadata and stage result structure for the firmware pipeline
- Inputs:
  - stage declarations from first-party planning code
- Outputs:
  - `StageDefinition`
  - `StageResult`
- Side effects:
  - none
- External dependencies:
  - none beyond stdlib dataclasses
- Validation status:
  - indirectly covered by tests through pipeline reporting
  - non-destructive
- Rewrite priority:
  - low
- Covered by tests:
  - indirect
- Non-destructive:
  - yes
- Dependents:
  - `odtslib/firmware_pipeline.py`

## `odtslib/tool_wrappers.py`

- Purpose:
  - Isolate external binary interaction behind Python interfaces
  - Validate binary existence
  - Attempt version/capability checks
  - Normalize failures into structured exceptions
- Inputs:
  - command arguments
  - binary path definitions
- Outputs:
  - `CommandResult`
  - `ToolValidation`
- Side effects:
  - may execute external binaries when not in dry-run
- External dependencies:
  - wrapped binaries in `resources/bin/`
  - optional interpreters found on `PATH`
- Validation status:
  - covered by tests for wrapper behavior
  - safe in dry-run
  - live execution still depends on host compatibility
- Rewrite priority:
  - medium
- Solves:
  - replaces raw shell-string execution in the modernized first-party paths
- Covered by tests:
  - yes, in `tests/test_tool_wrappers.py`
- Non-destructive:
  - wrapper interface itself yes in dry-run
  - live execution no
- Dependents:
  - `odts.py`
  - `odtslib/diagnostics.py`
  - `resources/img4.py` (partial)
  - `resources/pwn.py` (partial)

## `odtslib/device.py`

- Purpose:
  - Parse `irecovery -q` output
  - map `BDID` to board config using `resources/device_map.txt`
- Inputs:
  - `irecovery` output
  - device map text file
- Outputs:
  - parsed key/value device data
  - board config string
- Side effects:
  - none
- External dependencies:
  - `resources/device_map.txt`
- Validation status:
  - covered by tests
  - non-destructive
- Rewrite priority:
  - low
- Covered by tests:
  - yes, in `tests/test_device_helpers.py`
- Non-destructive:
  - yes
- Dependents:
  - `odts.py`

## `odtslib/diagnostics.py`

- Purpose:
  - collect non-destructive environment/dependency/resource/tool diagnostics
- Inputs:
  - local filesystem state
  - Python import availability
  - wrapped tool inspection
- Outputs:
  - structured diagnostic report
- Side effects:
  - none in current usage on unsupported host because tool validation is dry-run there
- External dependencies:
  - Python packages
  - wrapped binaries
- Validation status:
  - exercised through CLI
  - non-destructive
- Rewrite priority:
  - low
- Covered by tests:
  - no dedicated test, but exercised by CLI smoke check
- Non-destructive:
  - yes
- Dependents:
  - `odts.py`

## `odtslib/setup.py`

- Purpose:
  - inspect setup state
  - explicitly fetch supported repo-local missing resources
- Inputs:
  - fetchable resource registry
- Outputs:
  - setup report
  - download action list
- Side effects:
  - in non-dry-run mode, downloads archives and writes repo-local files
- External dependencies:
  - `requests`
  - remote GitHub-hosted archives
- Validation status:
  - partially covered by tests for inspection logic
  - dry-run is non-destructive
  - live network fetch unverified in this environment
- Rewrite priority:
  - medium
- Covered by tests:
  - inspection only
- Non-destructive:
  - yes in inspection/dry-run
  - no when fetching
- Dependents:
  - `odts.py`

## `resources/ipsw.py`

- Purpose:
  - safely read `BuildManifest.plist`
  - extract a local IPSW archive
- Inputs:
  - IPSW path
  - BuildManifest path
- Outputs:
  - extracted `IPSW/` tree
  - product version or supported models
- Side effects:
  - writes/deletes `IPSW/`
- External dependencies:
  - stdlib `zipfile`
- Validation status:
  - covered by tests
  - extraction is local filesystem only
- Rewrite priority:
  - low to medium
- Covered by tests:
  - yes, in `tests/test_ipsw.py`
- Non-destructive:
  - not fully, because it writes extracted files
- Dependents:
  - `odts.py`

## `odts.py`

- Purpose:
  - modernized CLI entrypoint
  - routes to diagnostics, setup, firmware validation, local/remote flow, and pwn-only mode
- Inputs:
  - CLI arguments
- Outputs:
  - user-facing status/logging
  - JSON reports
- Side effects:
  - depends on mode
  - diagnostics and validation are non-destructive
  - local/remote/pwn execution paths perform live actions
- External dependencies:
  - almost all first-party modules
  - wrapped binaries in execution modes
- Validation status:
  - partially validated
  - safe planning/diagnostic paths verified
  - live execution paths unverified on macOS
- Rewrite priority:
  - medium
- Covered by tests:
  - no direct CLI test suite
- Non-destructive:
  - yes for `--diagnostic`, `setup`, `--validate-firmware`, and `--dry-run`
  - no for live execution modes

## 2. Legacy Compatibility Modules

These modules are still relied upon in some capacity, but they remain legacy, partially migrated, or risky.

## `resources/img4.py`

- Purpose:
  - historically the main first-party firmware staging, patching, signing, and boot-sending implementation
- Inputs:
  - device model
  - iOS version
  - manifest
  - boot args
  - local/remote mode
  - board config
- Outputs:
  - staged firmware artifacts under `resources/StagedFiles/`
  - signed IMG4 payloads
  - `resources/shsh.shsh`
  - boot send commands issued to device
- Side effects:
  - heavy filesystem mutation
  - external tool execution
  - device interaction via `irecovery`
  - interactive pause in the current boot send path
- External dependencies:
  - `img4tool`
  - `img4`
  - `irecovery`
  - `iBoot64Patcher`
  - `Kernel64Patcher`
  - `dtree_patcher`
  - `ibootim`
  - `kairos`
  - `tsschecker`
  - `resources/pwn.py`
- Validation status:
  - partially modernized
  - manifest component lookup is now routed through the safe planner
  - execution logic remains mostly unverified
- Rewrite priority:
  - highest
- What remains legacy:
  - live patch/sign/send orchestration
  - residual raw subprocess usage
  - mixed planning and execution in one file
- What is still relied upon:
  - actual artifact staging and live execution paths
- What should be extracted:
  - tool execution
  - artifact generation
  - patch planning
  - stage-specific executors

## `resources/pwn.py`

- Purpose:
  - exploit orchestration and device-state transition helper
- Inputs:
  - connected DFU device state
  - detected CPID / serial number
- Outputs:
  - exploit invocation output
  - attempted pwned DFU transition
  - decrypted KBAG values in some paths
- Side effects:
  - device interaction
  - working-directory changes in legacy branches
  - execution of exploit binaries/scripts
- External dependencies:
  - `resources/ipwndfu/`
  - `resources/ipwndfu8012/`
  - `iPwnder32`
  - `eclipsa*`
  - external Python interpreters in some branches
- Validation status:
  - unverified
  - partially wrapper-isolated
- Rewrite priority:
  - very high, but security-sensitive
- What remains legacy:
  - most of the branch logic
  - low-level exploit assumptions
- What is still relied upon:
  - any live exploit-dependent flow
- What should be extracted:
  - state detection
  - exploit planning
  - explicit compatibility matrix

## `iospythontools/ipswapi.py`

- Purpose:
  - look up IPSW metadata from `ipsw.me`
  - extract files from remote IPSW archives
- Inputs:
  - device identifier
  - firmware version
- Outputs:
  - downloaded JSON metadata files
  - extracted remote archive members
- Side effects:
  - network access
  - writes JSON cache files in repo root
- External dependencies:
  - `remotezip`
  - `ipsw.me`
- Validation status:
  - lightly exercised by inspection only
  - not covered by tests
- Rewrite priority:
  - high
- What remains legacy:
  - network orchestration and local cache behavior
- What is still relied upon:
  - remote IPSW flow
- What should be extracted:
  - stable fetch/cache abstraction

## `iospythontools/manifest.py`

- Purpose:
  - older manifest helper for codename lookup
- Inputs:
  - device identifier
  - version
- Outputs:
  - downloaded BuildManifest
  - build train/codename lookup
- Side effects:
  - network access
  - local file creation/removal
- External dependencies:
  - `remotezip`
- Validation status:
  - legacy and untested
- Rewrite priority:
  - medium to high
- What remains legacy:
  - text-based manifest parsing
- What is still relied upon:
  - older iPhone Wiki helper path

## `iospythontools/iphonewiki.py`

- Purpose:
  - legacy path for looking up firmware keys from the iPhone Wiki
- Inputs:
  - device/version
- Outputs:
  - key dictionary
- Side effects:
  - network access
  - interactive prompt in multi-model pages
- External dependencies:
  - `bs4`
  - `theiphonewiki.com`
- Validation status:
  - effectively legacy
  - not covered by tests
- Rewrite priority:
  - medium
- What remains legacy:
  - network scraping
  - interactive behavior
- What is still relied upon:
  - currently not the main path; code mostly forces local KBAG decryption instead

## 3. External Binary Wrapper Boundary

All wrapped external tool calls now flow through `odtslib/tool_wrappers.py` in the modernized paths.

General contract:

- binary presence is validated before execution
- version/capability probing is attempted using configured help/version commands
- stdout/stderr/return code are captured in `CommandResult`
- failures are normalized as `ExternalToolError`
- dry-run skips execution and preserves shaped arguments

## Wrapped tools

## `irecovery`

- Presence validation:
  - file existence at `resources/bin/irecovery`
- Version/capability check:
  - attempts `-h`
- Failure normalization:
  - execution failures become `ExternalToolError`
- Stages depending on it:
  - device query
  - boot image send
  - boot command execution

## `tsschecker`

- Presence validation:
  - file existence at `resources/bin/tsschecker`
- Version/capability check:
  - attempts `-h`
- Failure normalization:
  - execution failures become `ExternalToolError`
- Stages depending on it:
  - SHSH acquisition

## `img4tool`

- Presence validation:
  - file existence at `resources/bin/img4tool`
- Version/capability check:
  - attempts `-h`
- Failure normalization:
  - execution failures become `ExternalToolError`
- Stages depending on it:
  - IMG4 metadata extraction
  - IMG4 signing
  - IM4P creation
  - decryption

## `img4`

- Presence validation:
  - file existence at `resources/bin/img4`
- Version/capability check:
  - attempts `-h`
- Failure normalization:
  - execution failures become `ExternalToolError`
- Stages depending on it:
  - kernel unpacking

## `ibootim`

- Presence validation:
  - file existence at `resources/bin/ibootim`
- Version/capability check:
  - attempts `-h`
- Failure normalization:
  - execution failures become `ExternalToolError`
- Stages depending on it:
  - boot logo conversion

## `iBoot64Patcher`, `Kernel64Patcher`, `dtree_patcher`, `kairos`

- Presence validation:
  - file existence in `resources/bin/`
- Version/capability check:
  - attempts `-h`
- Failure normalization:
  - execution failures become `ExternalToolError`
- Stages depending on them:
  - boot image patching
  - optional kernel patching
  - optional DeviceTree patching

## `iPwnder32`, `eclipsa8000`, `eclipsa8003`, `eclipsa7000`, `eclipsa7001`

- Presence validation:
  - file existence in `resources/bin/`
- Version/capability check:
  - limited; some only have existence/dry-run inspection
- Failure normalization:
  - execution failures become `ExternalToolError`
- Stages depending on them:
  - legacy exploit branches in `resources/pwn.py`

## Wrapper boundary limitations

- Not every legacy path is fully converted to wrappers yet.
- `resources/img4.py` and `resources/pwn.py` still contain deeper legacy execution logic beyond the currently migrated touchpoints.
- Version checks are best-effort. On Windows they are intentionally dry-run because the bundled binaries are Mach-O and cannot be executed meaningfully.

## 4. Missing Or Unverified Components

## Missing files/resources

- `resources/bin/tsschecker`
  - missing in current checkout
  - blocks SHSH generation
- `resources/ipwndfu8012/checkm8.py`
  - missing in current checkout
  - blocks some legacy exploit paths

## Unvalidated runtime assumptions

- bundled Mach-O tools will run correctly on the target Mac
- `irecovery` behavior matches the legacy expectations
- the boot send order in `resources/img4.py` is still valid
- the ramdisk still results in a mountable volume on current macOS

## Hardware-dependent paths

- all exploit logic in `resources/pwn.py`
- all DFU USB state transitions in `resources/ipwndfu*`
- all live image transfer logic in `resources/img4.py`

## macOS-only behaviors not verified here

- execution of Mach-O binaries in `resources/bin/`
- interaction with Apple device USB stack
- any security/policy behavior on current macOS
- post-boot visibility in Disk Utility / volume mount behavior

## 5. Execution Boundary

This is the strict current boundary between safe planning and live execution.

## Planning / inspection only

These modules only inspect, parse, or plan:

- `odtslib/firmware_manifest.py`
- `odtslib/firmware_pipeline.py`
- `odtslib/stage_model.py`
- `odtslib/device.py`
- `odtslib/diagnostics.py`
- safe portions of `odtslib/setup.py` in inspection/dry-run mode
- `odts.py` in:
  - `--diagnostic`
  - `setup`
  - `setup --fetch-missing --dry-run`
  - `--validate-firmware`

## Live execution begins here

The repository crosses from planning into action when it does any of the following:

- extracts a full IPSW to disk for operational use
- requests SHSH via `tsschecker`
- invokes patchers or IMG4 tools to transform artifacts
- calls `irecovery`
- executes exploit helpers

These action boundaries currently exist in:

- `odts.py`
  - `run_remote_flow`
  - `run_local_ipsw_flow`
  - `run_pwn_only`
- `resources/img4.py`
  - `img4stuff`
  - `sendImages`
  - AMFI patching path
- `resources/pwn.py`
  - all exploit branches

## Modules that still combine planning and execution

- `resources/img4.py`
  - now uses safe manifest planning for lookup
  - still mixes planning, staging, patching, signing, and boot execution
- `odts.py`
  - still orchestrates both safe validation and live execution modes in one file
- `resources/pwn.py`
  - still combines device-state detection and exploit execution

These are the main split candidates.

## 6. Recommended Next Rewrites

Top rewrite targets based on the current code:

1. `resources/img4.py`
   - Why:
     - still the largest concentration of mixed concerns
     - still contains residual raw subprocess usage
     - still mixes artifact planning with live execution
   - Value:
     - highest reduction in complexity and risk

2. `resources/pwn.py`
   - Why:
     - central legacy exploit orchestration file
     - hardware-sensitive and branch-heavy
     - still has unclear working-directory and interpreter assumptions
   - Value:
     - would establish a clear execution boundary around exploit behavior

3. `iospythontools/ipswapi.py`
   - Why:
     - remote IPSW flow still relies on legacy network/file cache behavior
     - writes JSON into repo root
     - not covered by tests
   - Value:
     - would stabilize remote planning and remote fetch behavior

4. `odts.py`
   - Why:
     - still carries multiple responsibilities
     - should be reduced to CLI parsing and dispatch only
   - Value:
     - improves maintainability and explicit mode boundaries

5. Legacy manifest/network helpers
   - Files:
     - `iospythontools/manifest.py`
     - `iospythontools/iphonewiki.py`
   - Why:
     - still text-based or scrape-based
     - currently low confidence and under-tested
   - Value:
     - removes stale fallback logic and clarifies supported data sources

## 7. Feature-Flag / Warning Candidates

These modules or paths should remain explicitly isolated behind warnings, legacy labels, or feature flags.

## Legacy / warning candidates

- `resources/pwn.py`
  - label as legacy and hardware-dependent
- live execution branches in `resources/img4.py`
  - label as unverified boot-chain execution
- AMFI patching
  - label as experimental/unverified
- dual-boot partition patching
  - label as legacy/unverified
- remote Wiki key lookup path
  - label as unsupported/legacy unless revalidated
- any path requiring missing resources:
  - `tsschecker`
  - `resources/ipwndfu8012/checkm8.py`

## Suggested flag/warning categories

- `legacy`
- `hardware-dependent`
- `macos-only`
- `missing-external-component`
- `unverified-boot-path`
- `experimental-patching`

## Summary Table

| Module/File | Status | Safe/Legacy/Unverified | Tests? | Side effects? | Rewrite priority |
|---|---|---|---|---|---|
| `odtslib/firmware_manifest.py` | Active structured parser | Safe | Yes | No | Low |
| `odtslib/firmware_pipeline.py` | Active structured planner | Safe | Yes | No | Low-Medium |
| `odtslib/stage_model.py` | Active stage model | Safe | Indirect | No | Low |
| `odtslib/tool_wrappers.py` | Active wrapper boundary | Safe for dry-run, live depends on tools | Yes | Yes when executing | Medium |
| `odtslib/device.py` | Active helper | Safe | Yes | No | Low |
| `odtslib/diagnostics.py` | Active diagnostics | Safe | Indirect | No | Low |
| `odtslib/setup.py` | Active setup helper | Safe in inspect/dry-run | Partial | Yes when fetching | Medium |
| `resources/ipsw.py` | Modernized local IPSW helper | Mostly safe | Yes | Yes, local filesystem writes | Low-Medium |
| `odts.py` | Modernized CLI/orchestrator | Mixed | No direct suite | Depends on mode | Medium |
| `resources/img4.py` | Partial migration only | Legacy/Unverified | No | Yes | Highest |
| `resources/pwn.py` | Partial migration only | Legacy/Unverified | No | Yes | Very High |
| `iospythontools/ipswapi.py` | Legacy remote fetch helper | Legacy | No | Yes | High |
| `iospythontools/manifest.py` | Legacy manifest helper | Legacy | No | Yes | Medium-High |
| `iospythontools/iphonewiki.py` | Legacy scrape helper | Legacy/Unverified | No | Yes | Medium |
| `resources/ipwndfu/` | Vendored exploit tree | Legacy/Unverified | No | Yes | Isolate, not guess |
| `resources/ipwndfu8012/` | Vendored exploit tree | Legacy/Unverified | No | Yes | Isolate, not guess |
| `resources/bin/*` | External native tools | Unverified | No | Yes | Wrap/isolate |
