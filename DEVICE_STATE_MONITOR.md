# Device State Monitor

## First 5 Minutes In The Lab

Run this first on the host Mac:

```bash
python odts.py --device-state
```

Possible states:

- `no_device`
  - no relevant device could be detected
  - check cable, DFU entry, and USB connection
- `tool_comm_failure`
  - the host could not communicate with the device through the inspection tool
  - check `irecovery`, permissions, and host compatibility
- `identifiers_partial`
  - some identifiers were found, but not enough for later stages
  - retry and confirm DFU/recovery stability
- `identifiers_ready`
  - the host can read the identifiers needed for later dry-run checks
  - proceed to `--dry-run` or `--validate-firmware`

If you want machine-readable output:

```bash
python odts.py --device-state --json
```

If you want detailed evidence and raw tool output:

```bash
python odts.py --device-state --verbose
```

## Purpose

The device-state monitor is a non-destructive inspection layer. It does not:

- send boot files
- alter device mode
- run exploit paths
- patch firmware

It only inspects and reports what the host can safely observe.

## Commands

Human-readable summary:

```bash
python odts.py --device-state
```

Machine-readable JSON:

```bash
python odts.py --device-state --json
```

Verbose human-readable output:

```bash
python odts.py --device-state --verbose
```

## What It Detects

When possible, the monitor reports:

- whether `irecovery` can query a connected relevant device
- whether identifiers such as `ECID`, `BDID`, `CPID`, or model/product strings are visible
- whether the current state is suitable for later dry-run validation
- which evidence was used to classify the state

## Current State Model

## `no_device`

- Meaning:
  - no relevant device data could be obtained
- Likely next step:
  - verify cable, DFU entry, and USB visibility
- Common causes:
  - no device connected
  - bad cable
  - wrong mode

## `usb_present_unknown`

- Meaning:
  - a relevant device may be present, but the monitor cannot classify it confidently
- Likely next step:
  - re-enter DFU/recovery and retry
- Common causes:
  - partial tool output
  - unsupported state

## `dfu_detected`

- Meaning:
  - reserved state for low-level DFU detection confidence
- Current note:
  - current implementation is conservative and mostly classifies based on safely read identifiers

## `recovery_detected`

- Meaning:
  - the device appears visible through `irecovery` but identifiers are incomplete
- Likely next step:
  - re-run the monitor and confirm ECID/BDID visibility

## `identifiers_partial`

- Meaning:
  - one or more useful identifiers were read, but not enough for later workflow confidence
- Likely next step:
  - retry and stabilize the device connection

## `identifiers_ready`

- Meaning:
  - the monitor found enough identifiers for later dry-run planning
- Likely next step:
  - proceed to:
    - `python odts.py --diagnostic --json`
    - `python odts.py -i iBridge2,5 6.1 --dry-run`

## `tool_comm_failure`

- Meaning:
  - the inspection tool exists but failed to communicate
- Likely next step:
  - test `./resources/bin/irecovery -q` directly
- Common causes:
  - host binary compatibility issue
  - permission issue
  - device not in the expected mode

## `unsupported_state`

- Meaning:
  - identifiers or behavior do not fit the currently understood workflow
- Likely next step:
  - capture output and compare against expected T2 identifiers

## Output Interpretation

Human-readable mode shows:

- detected state
- meaning
- whether later stages are likely compatible
- evidence used
- identifiers found
- tools used
- likely next step
- likely failure causes

JSON mode emits a structured object containing:

- `state`
- `meaning`
- `evidence`
- `identifiers`
- `tools`
- `likely_next_step`
- `likely_failure_causes`
- `compatible_with_later_stages`

## Common Failure Cases

## `irecovery` missing or non-runnable

- Symptoms:
  - `tool_comm_failure`
  - wrapper detail indicates execution failure
- Next step:
  - run `./resources/bin/irecovery -h`

## Device not actually in DFU/recovery-visible state

- Symptoms:
  - `no_device`
  - `tool_comm_failure`
- Next step:
  - re-enter DFU mode and retry

## Partial identifier output

- Symptoms:
  - `identifiers_partial`
- Next step:
  - retry and ensure the connection is stable before deeper workflow steps

## How To Use The Monitor Before Deeper Validation

Recommended order:

1. `python odts.py --device-state`
2. `python odts.py --diagnostic --json`
3. `python odts.py -i iBridge2,5 6.1 --dry-run`
4. only then attempt live device actions

This lets the operator distinguish:

- host/tool problems
- device visibility problems
- identifier-read problems
- later workflow/tooling problems
