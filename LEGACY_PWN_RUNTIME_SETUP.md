# Legacy Pwn Runtime Setup

## Scope

This document describes the smallest host-side setup steps needed to satisfy the declared legacy T8012 runtime contract.

It is non-destructive and host-only.

It does not run the chain.

## Check Command

Use:

```bash
./venv/bin/python odts.py --check-legacy-pwn-runtime
./venv/bin/python odts.py --check-legacy-pwn-runtime --json
```

## Current Host Result

Current verified host-side state for the selected Python `2.7.18` runtime:

- `interpreter_ready=true`
- `module_import_ready=false`
- `libusb_backend_ready=false`
- `vendored_libusbfinder_ready=false`

Current safe import result:

- selected interpreter resolves and reports `Python 2.7.18`
- the remaining import boundary is downstream of interpreter selection
- current concrete blockers are:
  - `missing_pyusb`
  - `missing_libusb`
  - `libusbfinder_packaging_issue`

Current packaging result:

- vendored `libusbfinder` is not clean for the current macOS host version

The checker now separates:

- `interpreter_ready`
- `module_import_ready`
- `libusb_backend_ready`
- `vendored_libusbfinder_ready`
- `preview_clean_runtime_boundary`

## Smallest Host-Side Remediation

### 1. Provide an explicit Python 2.7 interpreter

Required because:

- the declared contract requires an explicit legacy Python 2 runtime
- runtime readiness should not depend on `/usr/bin/python` or bare `python`

Expected export form:

```bash
export ODTS_LEGACY_PYTHON=/absolute/path/to/python2.7
```

This is the smallest host-only step that clears the interpreter-selection boundary.

### 2. Re-check the runtime contract

After setting the export:

```bash
./venv/bin/python odts.py --check-legacy-pwn-runtime
```

What this now tells you cleanly:

- `interpreter_ready` reflects interpreter presence and version only
- `module_import_ready` reflects whether `usb` imports in the selected interpreter
- `libusb_backend_ready` reflects whether `usb.backend.libusb1` imports in the selected interpreter
- `vendored_libusbfinder_ready` reflects whether the vendored bottle mapping is clean for the host
- `preview_clean_runtime_boundary` is only true when all of the above are true

### 3. Keep libusbfinder packaging explicit

Current remaining packaging and import issues are not solved by the interpreter export alone.

The vendored `resources/ipwndfu8012/libusbfinder/__init__.py` logic still assumes older macOS bottle mappings.

So even after Python 2.7 is available, the host may still report:

- `missing_pyusb`
- `missing_libusb`
- `libusbfinder_packaging_issue`

That is expected until the host-side USB import and vendored packaging boundary is handled explicitly.

If the selected-interpreter import probe still fails after Python 2.7 is available, use the checker output to isolate whether the remaining problem is:

- `module_import_ready=False`
- `libusb_backend_ready=False`
- `selected_interpreter_backend_issue_category=relative_import_issue`
- `selected_interpreter_backend_detail=ImportError: No module named util`

That specific signature should be treated as a packaging/import-boundary problem in the USB stack, not as an interpreter-presence failure.

## Smallest Safe Remediation Options

The current smallest host-only remediation options are:

- use `./scripts/bootstrap_lab_mac.sh` to make interpreter and package setup reproducible
- source `.odts-legacy-python.env` before running checks
- use `./venv/bin/python odts.py --check-legacy-pwn-runtime --json` to confirm exactly which layer still fails

What remains unresolved after bootstrap is expected to be one of:

- Python 2-side `pyusb` installation not visible to the selected interpreter
- backend import failure in the selected Python 2 environment
- vendored `libusbfinder` bottle mapping not matching the current macOS host

## What This Does Not Solve

Even after the host-side steps above:

- the legacy chain is still not approved for execution
- exploit behavior is still unknown
- device behavior is still unknown
- high-risk Python 2 behavior files remain unported by design

## Practical Goal

The practical goal of this setup work is:

- move the runtime boundary as close to `preview-clean` as possible
- make the remaining unresolved issue explicit and packaging-related
- avoid any exploit or hardware behavior changes
