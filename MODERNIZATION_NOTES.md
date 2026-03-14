# Modernization Notes

## Scope

This pass focused on maintainability and diagnosability, not on re-engineering the exploit chain or guessing undocumented boot behavior.

## What Changed

- Replaced the monolithic `odts.py` entrypoint with a Python 3 CLI wrapper that:
  - removes runtime dependency installation
  - removes unsafe host-modification behavior
  - adds `--diagnostic`, `--dry-run`, JSON output, and structured logging
  - adds an explicit `setup --fetch-missing` path for supported repo-local resource downloads
  - adds `--validate-firmware` for non-destructive manifest/IPSW planning
  - keeps legacy operational flags while surfacing explicit errors
- Added `odtslib/` for centralized configuration, cleanup, subprocess handling, device parsing, logging, and diagnostics.
- Added structured firmware planning modules:
  - `odtslib/firmware_manifest.py`
  - `odtslib/firmware_pipeline.py`
  - `odtslib/stage_model.py`
- Rewrote `resources/ipsw.py` into a Python 3-safe helper with deterministic extraction and manifest handling.
- Removed the first-party runtime download of Fugu from `resources/pwn.py`.
- Added binary wrappers in `odtslib/tool_wrappers.py` and routed the modernized top-level flow through them.
- Replaced brittle BuildManifest text slicing in the first-party planning path with plist-backed component selection.
- Added a minimal `.gitignore`.
- Reduced `requirements.txt` to runtime dependencies only.
- Added lightweight unit tests for safe helper logic.

## What Was Intentionally Not Rewritten

- Vendored exploit internals in `resources/ipwndfu*`
- core IMG4 staging logic in `resources/img4.py`
- bundled Mach-O binaries under `resources/bin/`

Those areas are security-sensitive, hardware-dependent, or both. They remain documented as legacy components pending macOS validation.

## Known Remaining Gaps

- `resources/img4.py` is still a very large, shell-heavy module with fragile plist parsing.
- not all execution paths inside `resources/img4.py` have been migrated away from raw subprocess usage yet
- Python 2 vendored code still exists in the repo and may be required by some hardware paths.
- Some non-T8012 branches in `resources/pwn.py` reference tooling that is not present in this checkout.
- Actual exploit/boot flows were not validated on macOS during this pass.

## Parsed Safely

- local BuildManifest loading and parsing
- board-specific BuildIdentity selection
- board-specific firmware component lookup
- staged artifact planning and stage reporting

## Still Legacy

- exploit internals
- device-state transitions into pwned DFU
- most low-level patch execution paths
- actual live boot chain send/boot behavior

## Next Validation Step

Run `python odts.py --diagnostic --json` on the target Mac first, then exercise `--dry-run` for the intended workflow before attempting real device actions.
