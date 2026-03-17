# Enter Pwned DFU Analysis

## Scope

This document describes the current `enter-pwned-dfu` execution-side boundary for the connected T8012 lab target.

It is analysis only.

It does not execute the step.

## Call Graph

Current call path for the T8012 branch:

1. `odts.py`
2. `run_pwn_only()` or the live local/remote IPSW flow
3. `resources.pwn.pwndfumode()`
4. `resources/ipwndfu8012/ipwndfu -p`
5. sleep for 5 seconds
6. reacquire DFU device through `resources.ipwndfu.dfu.acquire_device()`
7. inspect serial number for `PWND:[checkm8]`
8. if present, run `python resources/ipwndfu8012/nop_image4.py`

## Exact Commands

The legacy T8012 path would run these commands from the repo root:

```bash
/Users/kocrrd/Documents/t8012-DTS/resources/ipwndfu8012/ipwndfu -p
python /Users/kocrrd/Documents/t8012-DTS/resources/ipwndfu8012/nop_image4.py
```

Notes:

- `ipwndfu` is executed directly through its shebang.
- `nop_image4.py` is invoked through bare `python` from `resources/pwn.py`.
- the reacquire-and-check step is in-process Python code, not a subprocess command.

## CWD Assumptions

The current wrapper-side subprocess helpers use:

- cwd: repo root `/Users/kocrrd/Documents/t8012-DTS`

Legacy code in `resources/pwn.py` also still contains `os.chdir("resources/ipwndfu8012")` logic, but the modern helper functions `_run_repo_binary()` and `_run_python_tool()` explicitly force subprocess cwd back to the repo root.

Meaning:

- subprocess cwd is stable and deterministic at the repo root
- import resolution relies on Python setting `sys.path[0]` to the script directory when the script is executed by path

## File Dependencies

Directly referenced files for the current T8012 branch:

- `resources/pwn.py`
- `resources/ipwndfu8012/ipwndfu`
- `resources/ipwndfu8012/nop_image4.py`
- `resources/ipwndfu8012/checkm8.py`
- `resources/ipwndfu8012/t8012_heap_fix.py`
- `resources/ipwndfu8012/dfu.py`
- `resources/ipwndfu8012/usbexec.py`

Effective runtime dependencies also include:

- `resources/ipwndfu8012/device_platform.py`
- `resources/ipwndfu8012/libusbfinder.py`
- Python USB stack modules imported by the legacy helpers

## Environment Assumptions

The T8012 legacy path assumes:

- a Python 2 runtime is available for `resources/ipwndfu8012/ipwndfu`
- `/usr/bin/python` exists for the `ipwndfu` shebang
- a `python` launcher exists on PATH for `nop_image4.py`
- the interpreter used for `nop_image4.py` can also import Python 2-era helper modules
- PyUSB/libusb access works for the legacy DFU helpers
- USB re-enumeration after the exploit is stable enough for the 5-second wait-and-reacquire pattern

## Expected Pre-State

Before entering the step, legacy code expects:

- device attached
- device in DFU-capable pre-exploit state
- serial contains `CPID:8012`
- serial does not already contain `PWND:[checkm8]`

## Expected Post-State

If the step works as intended:

- `ipwndfu -p` transitions the device into pwned DFU
- the re-acquired serial contains `PWND:[checkm8]`
- `nop_image4.py` patches out `image_load`
- `nop_image4.py` prints:
  - `Removed image_load call; all incoming images will be loaded as raw`
- `nop_image4.py` performs DFU abort and USB reset before returning

## Stdout / Stderr Patterns

Observed or declared success patterns:

- `Device is now in pwned DFU Mode.`
- `Exploit worked! patching out signature checks`
- `Removed image_load call; all incoming images will be loaded as raw`

Observed or expected failure patterns:

- `ERROR: Exploit failed. Device did not enter pwned DFU Mode.`
- `ERROR: No Apple device`
- `Exploit failed, reboot device into DFU mode and press enter to re-run checkm8`

Current host-specific modern macOS failure patterns:

- `script shebang requires missing interpreter /usr/bin/python`
- `bad interpreter: /usr/bin/python: no such file or directory`
- `command not found: python`
- `SyntaxError`
- `No module named usb`
- `No module named libusbfinder`

## Likely Failure Points On Modern macOS

Current preview results identify these likely breakpoints:

1. `resources/ipwndfu8012/ipwndfu` is a Python 2 script with `#!/usr/bin/python`.
2. Modern macOS on this host does not provide `/usr/bin/python`.
3. `resources/pwn.py` launches `nop_image4.py` with bare `python`, but no `python` launcher exists on this host.
4. `resources/ipwndfu8012/dfu.py` and `resources/ipwndfu8012/usbexec.py` contain Python 2 constructs, so a Python 3 fallback would still be incompatible.
5. The legacy path depends on PyUSB/libusb outside the modern wrapper layer.
6. The step contains a fixed sleep and DFU reacquire sequence that has not been observed in this lab.

## Current Preview Mode

The non-destructive preview command is:

```bash
./venv/bin/python odts.py --preview-enter-pwned-dfu
./venv/bin/python odts.py --preview-enter-pwned-dfu --json
```

It performs:

- exact call-path rendering
- exact command rendering
- dependency file existence checks
- safe launcher probing for `ipwndfu`
- interpreter contract checks
- static compatibility checks for the `nop_image4.py` helper chain

It does not:

- touch the device
- execute the exploit
- execute `nop_image4.py`

## Current Conclusion

The first execution-side step is still `unverified`.

On this host, the first concrete blocker is not exploit semantics but execution environment compatibility:

- missing `/usr/bin/python`
- missing `python` launcher
- Python 2-only transitive helper chain under `resources/ipwndfu8012`

This is the current boundary before any future controlled live-step testing should be considered.
