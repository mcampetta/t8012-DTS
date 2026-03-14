# Known Breakpoints

## Missing External Components

- `resources/bin/tsschecker` is currently absent in this checkout.
- `resources/ipwndfu8012/checkm8.py` is currently absent in this checkout.

These block real SHSH acquisition and parts of the exploit path.

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

## Parsed Safely

- BuildManifest files used for first-party planning and board-specific artifact lookup
- board configuration selection from parsed manifests
- stage metadata and artifact planning

## Still Unverifiable Here

- actual macOS execution of bundled Mach-O binaries
- USB/DFU state transitions
- boot chain ordering on real hardware
- post-boot ramdisk behavior

## High-Risk Areas Remaining

- residual raw subprocess usage in deeper legacy sections of `resources/img4.py`
- Python 2 runtime dependencies in vendored exploit code
- hard dependency on external services for remote IPSW flows
- incomplete boot send routine in `resources/img4.py`

