# Pwn Runtime Audit

## Scope

This is a non-destructive runtime compatibility audit for the current `enter-pwned-dfu` chain.

It covers the T8012 path that would be reached from:

- `resources/ipwndfu8012/ipwndfu -p`
- `resources/ipwndfu8012/nop_image4.py`

It does not execute the chain.

## Entry Points

Current legacy entry points:

- `resources/ipwndfu8012/ipwndfu`
  - command: `/Users/kocrrd/Documents/t8012-DTS/resources/ipwndfu8012/ipwndfu -p`
  - shebang: `#!/usr/bin/python`
- `resources/ipwndfu8012/nop_image4.py`
  - command: `python /Users/kocrrd/Documents/t8012-DTS/resources/ipwndfu8012/nop_image4.py`
  - shebang: none

## Imported Python Files

Static audit of the current chain reaches these local Python files:

- `resources/ipwndfu8012/ipwndfu`
- `resources/ipwndfu8012/nop_image4.py`
- `resources/ipwndfu8012/dfu.py`
- `resources/ipwndfu8012/nor.py`
- `resources/ipwndfu8012/utilities.py`
- `resources/ipwndfu8012/alloc8.py`
- `resources/ipwndfu8012/checkm8.py`
- `resources/ipwndfu8012/image3_24Kpwn.py`
- `resources/ipwndfu8012/limera1n.py`
- `resources/ipwndfu8012/SHAtter.py`
- `resources/ipwndfu8012/steaks4uce.py`
- `resources/ipwndfu8012/usbexec.py`
- `resources/ipwndfu8012/t8012_heap_fix.py`
- `resources/ipwndfu8012/dfuexec.py`
- `resources/ipwndfu8012/image3.py`
- `resources/ipwndfu8012/device_platform.py`
- `resources/ipwndfu8012/recovery.py`
- `resources/ipwndfu8012/libusbfinder/__init__.py`
- vendored `resources/ipwndfu8012/usb/...` package files used by the legacy USB stack

## Interpreter Assumptions

Current chain assumptions:

- `/usr/bin/python` exists for the `ipwndfu` shebang
- `python` exists on PATH for `nop_image4.py`
- the interpreter can execute Python 2-era syntax across the imported helper chain

Current host result:

- `/usr/bin/python`: missing
- `python` on PATH: missing
- `python2` on PATH: missing
- `python2.7` on PATH: missing

## Shebangs

Direct entry-point shebangs:

- `resources/ipwndfu8012/ipwndfu`: `#!/usr/bin/python`
- `resources/ipwndfu8012/nop_image4.py`: none

## Python 2-Only Constructs Found

Representative Python 2-only constructs were found in:

- `resources/ipwndfu8012/ipwndfu`
  - print statements
  - `.decode('hex')`
- `resources/ipwndfu8012/dfu.py`
  - print statements
- `resources/ipwndfu8012/usbexec.py`
  - print statements
  - `long`
- `resources/ipwndfu8012/checkm8.py`
  - print statements
  - `.decode('hex')`
- `resources/ipwndfu8012/dfuexec.py`
  - print statements
- `resources/ipwndfu8012/libusbfinder/__init__.py`
  - print statements
  - `cStringIO`
  - `.decode('hex')`

The audit also found additional Python 2 print usage in other imported legacy modules such as:

- `resources/ipwndfu8012/utilities.py`
- `resources/ipwndfu8012/alloc8.py`
- `resources/ipwndfu8012/limera1n.py`
- `resources/ipwndfu8012/SHAtter.py`
- `resources/ipwndfu8012/steaks4uce.py`
- `resources/ipwndfu8012/recovery.py`

## External Binary / Tool Assumptions

The chain assumes:

- shebang-based execution of `resources/ipwndfu8012/ipwndfu`
- PATH-based resolution of `python` for `nop_image4.py`
- PyUSB-compatible `usb` runtime
- libusb access through the vendored `libusbfinder` flow

No modern first-party ODTS wrapper is used inside this chain after entry.

## CWD Assumptions

The current modern wrapper calls subprocesses from the repo root:

- cwd: `/Users/kocrrd/Documents/t8012-DTS`

The legacy scripts then rely on script-directory imports such as:

- `import dfu`
- `import usbexec`
- `import libusbfinder`

So the runtime contract still assumes:

- stable repo checkout layout
- execution by path
- script-local sibling imports resolving correctly

## Environment Variables / PATH Assumptions

Observed assumptions:

- `PATH` must contain `python` for `nop_image4.py`
- shebang resolution must find `/usr/bin/python`
- no environment-variable override exists for interpreter selection
- no environment-variable override exists for alternate runtime roots

## Blocker Classification

Current blocker chain from the static audit:

### interpreter_missing

- `resources/ipwndfu8012/ipwndfu`
  - shebang requires missing `/usr/bin/python`

### path_assumption

- `resources/pwn.py` launches `nop_image4.py` with bare `python`
  - no `python` launcher exists on this host

### python2_syntax_dependency

- direct dependency files:
  - `resources/ipwndfu8012/ipwndfu`
  - `resources/ipwndfu8012/dfu.py`
  - `resources/ipwndfu8012/usbexec.py`
- broader transitive legacy chain also includes Python 2-only files such as:
  - `checkm8.py`
  - `dfuexec.py`
  - `libusbfinder/__init__.py`
  - multiple exploit helper modules

### macOS runtime assumption

- `resources/ipwndfu8012/libusbfinder/__init__.py`
  - hard-coded around older macOS bottle mappings and Python 2-era code paths
- vendored USB/libusb stack compatibility on current macOS is still an assumption, not a validated fact

### unknown

- device behavior after exploit launch remains unknown because this audit does not execute the chain

## Current Conclusion

The current blocker chain is primarily runtime compatibility, not payload sourcing and not yet device behavior.

Meaning:

- the repo is blocked before any meaningful live exploit observation
- the first unresolved layer is interpreter/runtime compatibility

Even if the runtime blockers were solved, the following would still remain unknown:

- actual exploit behavior on the connected device
- USB re-enumeration timing after the `ipwndfu -p` stage
- whether `PWND:[checkm8]` is observed as expected
- whether `nop_image4.py` succeeds after a real pwned DFU transition
- whether later live send/boot stages behave as planned

## Audit Command

Use this non-destructive command to regenerate the runtime audit:

```bash
./venv/bin/python odts.py --audit-enter-pwned-dfu-runtime
./venv/bin/python odts.py --audit-enter-pwned-dfu-runtime --json
```
