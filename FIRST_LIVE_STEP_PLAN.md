# First Live Step Plan

## Scope

This plan covers only the first execution-side step:

- `enter-pwned-dfu`

It does not include the later boot-chain send path.

It does not authorize execution by itself.

## Exact Command To Run

When the runtime boundary is accepted for a controlled lab attempt, run:

```bash
ODTS_LEGACY_PYTHON=/absolute/path/to/python2.7 ./venv/bin/python odts.py -p --log-file logs/enter-pwned-dfu.log
```

If the interpreter export is already set in the shell:

```bash
./venv/bin/python odts.py -p --log-file logs/enter-pwned-dfu.log
```

## Required Preconditions

- host is the prepared lab macOS machine
- connected target is the intended T2 device
- device is detectable with:
  - `./venv/bin/python odts.py --device-state --verbose`
- payload readiness is still good:
  - payload build: `19P647`
- signing-material readiness is still good:
  - `resources/shsh.shsh` present
  - SHSH build used: `23P3120`
  - SHSH fallback to latest signed used: `true`
  - host-side artifact compatibility succeeded: `true`
- preflight still reports no blockers:
  - `./venv/bin/python odts.py --preflight`
- legacy runtime boundary has been rechecked immediately before the attempt:
  - `./venv/bin/python odts.py --preview-enter-pwned-dfu`
  - `./venv/bin/python odts.py --audit-enter-pwned-dfu-runtime`
  - `./venv/bin/python odts.py --check-legacy-pwn-runtime`
- operator is prepared to stop after the first step only

## Exact Logs To Capture

Capture these before the attempt:

```bash
./venv/bin/python odts.py --device-state --verbose
./venv/bin/python odts.py --prepare-device --json
./venv/bin/python odts.py --acquire-shsh --json
./venv/bin/python odts.py --preflight --json
./venv/bin/python odts.py --preview-enter-pwned-dfu --json
./venv/bin/python odts.py --audit-enter-pwned-dfu-runtime --json
./venv/bin/python odts.py --check-legacy-pwn-runtime --json
```

Capture during the attempt:

- full terminal stdout/stderr
- `logs/enter-pwned-dfu.log`
- device mode before command start
- device mode immediately after return or failure
- any USB disconnect/reconnect timing observed by the operator

## Expected Success Signals

- `resources/ipwndfu8012/ipwndfu -p` completes without an immediate launcher/runtime failure
- device re-enumerates and is reacquired
- serial contains `PWND:[checkm8]`
- output includes one or more of:
  - `Device is now in pwned DFU Mode.`
  - `Exploit worked! patching out signature checks`
  - `Removed image_load call; all incoming images will be loaded as raw`

## Expected Failure Signals

- `bad interpreter`
- `command not found`
- `SyntaxError`
- `ImportError`
- `No module named usb`
- `No module named libusbfinder`
- `ERROR: Exploit failed. Device did not enter pwned DFU Mode.`
- `ERROR: No Apple device`
- device disappears and does not return in the expected mode

## Device State Before And After

Before:

- connected
- detectable by `irecovery`
- identifiers available
- expected mode: Recovery or DFU-capable pre-exploit state, as confirmed by `--device-state`

After success:

- device should be in pwned DFU
- serial should indicate `PWND:[checkm8]`
- no later boot images should be sent in this test

After failure:

- device may remain in original mode, disconnect, or re-enumerate unexpectedly
- stop and capture state with `./venv/bin/python odts.py --device-state --verbose`

## Abort / Stop Conditions

Stop immediately if any of the following occur:

- pre-attempt readiness output no longer matches:
  - payload build `19P647`
  - SHSH build used `23P3120`
  - fallback used `true`
  - host-side artifact compatibility succeeded `true`
- `--preview-enter-pwned-dfu` or `--check-legacy-pwn-runtime` reports new runtime blockers
- any unexpected prompt, hang, or retry loop appears
- the device disconnects unexpectedly
- the device enters an unexpected mode
- command output differs materially from the expected first-step patterns
- the operator cannot confirm post-step state

## Current Readiness Interpretation

This plan is ready to use as a controlled test procedure, but the repo is still classified as:

- `ready for planning only`

The remaining unknown is execution-side behavior of `enter-pwned-dfu`, not payload sourcing or host-side SHSH artifact generation.
