# Legacy Pwn Runtime Contract

## Scope

This document defines the runtime contract for the legacy `enter-pwned-dfu` chain.

It is the source of truth for:

- interpreter selection
- launcher expectations
- supported host assumptions on modern macOS

It does not imply that the chain is safe to execute.

## Declared Interpreter Contract

The legacy T8012 pwn chain is declared to require an explicit Python 2 runtime.

Supported launch contract:

1. preferred:
   - set `ODTS_LEGACY_PYTHON` to an executable Python 2 interpreter path
2. fallback:
   - discover `python2.7` on PATH
   - otherwise discover `python2` on PATH

Unsupported contract:

- `/usr/bin/python` as an implicit system dependency
- bare `python` as an implicit PATH dependency
- Python 3 as a drop-in runtime for the unported legacy chain

## Launcher Behavior

Within ODTS, host-shim launchers should invoke legacy T8012 scripts explicitly as:

```bash
$ODTS_LEGACY_PYTHON resources/ipwndfu8012/ipwndfu -p
$ODTS_LEGACY_PYTHON resources/ipwndfu8012/nop_image4.py
```

or the equivalent discovered `python2.7` / `python2` path.

The same explicit interpreter should be used for both:

- `ipwndfu`
- `nop_image4.py`

## Supported On Modern macOS

Current safe statement:

- modern macOS is only supported for preview/audit by default
- a future controlled live-step attempt would require an explicit Python 2 runtime contract
- Python 3 is not currently a supported runtime for the unported legacy T8012 chain

## Dependency Packaging Contract

Even with an explicit legacy Python interpreter, the chain still assumes:

- PyUSB importability
- libusb backend availability
- vendored `libusbfinder` compatibility with the host macOS release

Those are separate packaging/runtime checks and must be reported explicitly by diagnostics.

## Preview-Clean Meaning

For this chain, `preview-clean` means:

- explicit legacy interpreter selected
- no remaining implicit `/usr/bin/python` or bare `python` launch assumptions
- dependency packaging issues are explicitly known
- preview/audit output is clear about any remaining runtime blockers

It does not mean:

- device behavior is validated
- exploit behavior is validated
- live execution is approved

## Host Check Command

Use this host-only command to validate the declared contract:

```bash
./venv/bin/python odts.py --check-legacy-pwn-runtime
./venv/bin/python odts.py --check-legacy-pwn-runtime --json
```
