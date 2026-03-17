# Enter Pwned DFU Remediation Plan

## Scope

This document is a safe modernization triage plan for the legacy runtime chain behind `enter-pwned-dfu`.

It does not:

- execute the chain
- interact with hardware
- attempt exploit restoration
- perform a broad port

The goal is only to identify the smallest credible path from:

- `runtime blocked`

to:

- `preview-clean and eligible for first controlled live-step test`

## Current State

Current blocker type is runtime compatibility, not payload sourcing.

Direct blockers already identified:

- missing `/usr/bin/python`
- bare `python` PATH assumption in `resources/pwn.py`
- Python 2-only dependencies in the T8012 chain
- older macOS/libusb assumptions in vendored `libusbfinder`

## Triage Table

### `resources/ipwndfu8012/ipwndfu`

- classification: `host shim only`
- why it fails on modern macOS:
  - shebang is `#!/usr/bin/python`
  - modern macOS no longer provides `/usr/bin/python`
  - file also contains Python 2-only syntax, so changing the launcher alone is not sufficient for real execution
- smallest safe remediation:
  - preview/diagnostic phase: stop executing through the shebang in diagnostics and model it as an explicit interpreter contract
  - future live-test prep phase: introduce an explicit, repo-controlled interpreter selection path instead of relying on `/usr/bin/python`
- remediation type:
  - diagnostic-only if limited to preview/audit/reporting
  - behavior-changing if the real live path is updated to call a different interpreter

### `resources/pwn.py`

- classification: `host shim only`
- why it fails on modern macOS:
  - launches `nop_image4.py` via bare `python`
  - current host has no `python` launcher on PATH
- smallest safe remediation:
  - replace the implicit `python` assumption with an explicit interpreter contract in preview and, later, in the live path if a controlled test is approved
- remediation type:
  - diagnostic-only if restricted to preview/audit
  - behavior-changing if the actual launch command is changed

### `resources/ipwndfu8012/dfu.py`

- classification: `moderate-risk port candidate`
- why it fails on modern macOS:
  - Python 2 print statements
  - depends on PyUSB/libusb behavior and device acquisition logic
  - directly touches the USB device at runtime
- smallest safe remediation:
  - do not port yet
  - keep it classified and isolated as a runtime blocker
  - if later approved, port syntax only in a tightly scoped branch with no logic changes
- remediation type:
  - behavior-changing, because this file directly participates in device communication

### `resources/ipwndfu8012/usbexec.py`

- classification: `high-risk behavior-sensitive file`
- why it fails on modern macOS:
  - Python 2 print statements
  - `long` type usage
  - tightly coupled to pwned DFU USB memory read/write behavior
- smallest safe remediation:
  - do not port in the first remediation slice
  - keep it behind preview/audit only until interpreter and packaging blockers are resolved
- remediation type:
  - behavior-changing and high-risk

### `resources/ipwndfu8012/checkm8.py`

- classification: `high-risk behavior-sensitive file`
- why it fails on modern macOS:
  - Python 2-only syntax and `.decode('hex')`
  - exploit implementation details are behavior-sensitive
  - depends on USB backend internals
- smallest safe remediation:
  - no direct changes in the first remediation slice
  - treat as execution-sensitive and keep out of any “preview-clean” work
- remediation type:
  - behavior-changing and high-risk

### `resources/ipwndfu8012/dfuexec.py`

- classification: `high-risk behavior-sensitive file`
- why it fails on modern macOS:
  - Python 2 print statements
  - participates in pwned DFU execution and command transport
- smallest safe remediation:
  - no direct changes in the first remediation slice
  - leave blocked and explicitly documented
- remediation type:
  - behavior-changing and high-risk

### `resources/ipwndfu8012/libusbfinder/__init__.py`

- classification: `external dependency packaging issue`
- why it fails on modern macOS:
  - Python 2-only constructs including `cStringIO`
  - hard-coded bottle mappings for older macOS versions
  - assumes an older libusb packaging model
- smallest safe remediation:
  - do not port in the first execution-prep slice
  - replace with an explicit host dependency contract in diagnostics, or later package a modern libusb dependency path outside the exploit logic
- remediation type:
  - diagnostic-only if limited to dependency declaration
  - behavior-changing if runtime backend loading is altered

### `resources/ipwndfu8012/utilities.py`

- classification: `low-risk Python 3 port candidate`
- why it fails on modern macOS:
  - Python 2 print syntax
- smallest safe remediation:
  - syntax-only modernization if this file becomes part of a future minimal interpreter-compatibility pass
- remediation type:
  - behavior-changing in principle, but relatively low-risk compared with USB-facing files

### `resources/ipwndfu8012/alloc8.py`

- classification: `moderate-risk port candidate`
- why it fails on modern macOS:
  - Python 2 print syntax
  - exploit-adjacent helper logic
- smallest safe remediation:
  - defer until after launcher/interpreter contracts are solved
- remediation type:
  - behavior-changing

### `resources/ipwndfu8012/limera1n.py`

- classification: `high-risk behavior-sensitive file`
- why it fails on modern macOS:
  - Python 2 print syntax
  - exploit implementation
- smallest safe remediation:
  - none in the first slice
- remediation type:
  - behavior-changing and high-risk

### `resources/ipwndfu8012/SHAtter.py`

- classification: `high-risk behavior-sensitive file`
- why it fails on modern macOS:
  - Python 2 print syntax
  - exploit implementation
- smallest safe remediation:
  - none in the first slice
- remediation type:
  - behavior-changing and high-risk

### `resources/ipwndfu8012/steaks4uce.py`

- classification: `high-risk behavior-sensitive file`
- why it fails on modern macOS:
  - Python 2 print syntax
  - exploit implementation
- smallest safe remediation:
  - none in the first slice
- remediation type:
  - behavior-changing and high-risk

### `resources/ipwndfu8012/recovery.py`

- classification: `moderate-risk port candidate`
- why it fails on modern macOS:
  - Python 2 print syntax
  - USB recovery transport behavior
- smallest safe remediation:
  - defer until a deliberate Python-compatibility pass is approved
- remediation type:
  - behavior-changing

## Smallest Subset Required For “Preview-Clean”

The smallest possible subset of changes needed to move from `runtime blocked` to `preview-clean and eligible for first controlled live-step test` is:

1. Remove the implicit interpreter assumptions.
   - make the T8012 launch contract explicit instead of relying on `/usr/bin/python`
   - remove the bare `python` PATH assumption from the live-step launcher path

2. Establish one declared runtime target for the legacy chain.
   - either a dedicated Python 2 runtime contract
   - or a tightly scoped compatibility layer

3. Resolve the minimum transitive syntax blockers reached by the T8012 path.
   - at minimum this still touches more than one file:
     - `ipwndfu`
     - `dfu.py`
     - `usbexec.py`
     - `checkm8.py`
     - `dfuexec.py`
     - `libusbfinder/__init__.py`

4. Re-run:
   - `--preview-enter-pwned-dfu`
   - `--audit-enter-pwned-dfu-runtime`

Important conclusion:

- the minimal set is not a one-line host shim
- the first meaningful slice is still a multi-file runtime-compatibility effort
- that effort can be staged narrowly, but it is not purely cosmetic

## Recommended Order Of Operations

Recommended lowest-risk sequence:

1. Lock the interpreter contract first.
   - decide whether the legacy chain is expected to run under a packaged Python 2 runtime or a future compatibility port
   - do this in diagnostics and documentation before touching live behavior

2. Eliminate implicit launcher assumptions.
   - remove dependence on `/usr/bin/python`
   - remove dependence on bare `python` on PATH

3. Isolate dependency packaging from behavior.
   - handle `libusbfinder` and libusb expectations as an explicit host/runtime dependency problem
   - do not mix this with exploit logic changes

4. Only then consider a tightly scoped syntax-compatibility pass.
   - start with the smallest transitive set reached by the T8012 path
   - keep USB/exploit behavior untouched except where syntax conversion is unavoidable

5. Re-audit before any live attempt.
   - `--preview-enter-pwned-dfu`
   - `--audit-enter-pwned-dfu-runtime`
   - if both are clean, reassess readiness for a first controlled live-step test

## What Still Remains Unknown After Runtime Remediation

Even if the runtime blockers above are solved, the following would still remain unknown:

- actual device-side exploit behavior
- whether the device enters `PWND:[checkm8]` as expected
- whether the 5-second sleep-and-reacquire timing is still valid
- whether `nop_image4.py` succeeds after a real pwned DFU transition
- whether later live send/boot stages behave correctly

So runtime remediation alone would move the repo toward:

- `preview-clean and eligible for first controlled live-step test`

It would not prove:

- end-to-end exploit success
- safe live execution behavior
