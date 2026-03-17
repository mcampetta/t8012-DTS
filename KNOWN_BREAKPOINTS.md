# Known Breakpoints

## Current Host Runtime Blockers

- Bundled `resources/bin/irecovery` is present but not host-runnable on this Mac:
  - fails with a dyld loader error for `/usr/local/lib/libirecovery.3.dylib`
- Bundled `resources/bin/ibootim` is present but not host-runnable on this Mac:
  - fails with a dyld loader error for `/usr/local/lib/libpng16.16.dylib`
- A working system/Homebrew `irecovery` is available at `/opt/homebrew/bin/irecovery`
  - first-party wrappers should prefer it over the stale bundled copy

These are environment/runtime compatibility issues, not missing-file issues.

## Legacy Components Still Isolated

- `resources/ipwndfu/`
- `resources/ipwndfu8012/`
- large portions of `resources/pwn.py`
- low-level execution sections of `resources/img4.py`

These remain isolated but not fully validated or rewritten.

## Still Legacy But Wrapped

- `irecovery`
- `img4tool`
- `img4`
- `ibootim`
- `iBoot64Patcher`
- `Kernel64Patcher`
- `dtree_patcher`
- `kairos`
- `iPwnder32`
- `eclipsa*`

The first-party code now accesses these through wrappers where modernization has reached, but the binaries themselves remain legacy external tools.

## Binary Resolution Status

- First-party wrapper resolution now probes candidates in priority order and selects the first runnable binary
- Candidate probe failures are separated into:
  - missing binary
  - not executable
  - loader failure
  - bad exit code
  - runnable
- `--device-state` now reports the selected `irecovery` path and rejection reasons for other candidates

## Parsed Safely

- BuildManifest files used for first-party planning and board-specific artifact lookup
- board configuration selection from parsed manifests
- stage metadata and artifact planning

## Still Unverifiable Here

- actual end-to-end success of all bundled Mach-O binaries on this host
- USB/DFU state transitions
- boot chain ordering on real hardware
- post-boot ramdisk behavior

## High-Risk Areas Remaining

- residual raw subprocess usage in deeper legacy sections of `resources/img4.py`
- Python 2 runtime dependencies in vendored exploit code
- hard dependency on external services for remote IPSW flows
- incomplete boot send routine in `resources/img4.py`
