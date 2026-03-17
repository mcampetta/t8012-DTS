# Operator Workflow

## Goal

Use one command to move a connected target into a known planning/preflight state without touching exploit or live execution behavior.

## Primary Command

Default safe remote sourcing flow:

```bash
./venv/bin/python odts.py --prepare-device
```

Force a specific build:

```bash
./venv/bin/python odts.py --prepare-device --build 19P647
```

Use a local IPSW instead of remote sourcing:

```bash
./venv/bin/python odts.py --prepare-device --ipsw /path/to/restore.ipsw
```

Structured output:

```bash
./venv/bin/python odts.py --prepare-device --json
```

## What It Does

`--prepare-device` orchestrates existing safe helpers only:

- detects the connected device
- reads identifiers
- derives product and board config
- selects the repo-aligned build by default unless `--build` is supplied
- prepares payloads into the canonical `IPSW/` layout
- runs non-destructive preflight
- reports the resulting readiness level

The current T2 path is hybrid by design:

- it uses pwned-DFU / `nop_image4.py` to relax Image4 handling
- it still uses SHSH-backed signing for most transmitted boot artifacts

So SHSH is still functionally required overall in the current implementation.

It does not:

- enter pwned DFU
- execute the legacy chain
- send payloads to hardware
- change device state

## Payload Source Selection

- if `--ipsw /path/to/restore.ipsw` is supplied:
  - use the local payload-layout helper
- otherwise:
  - use the safe remote payload helper

In both cases the command extracts planned payloads into the canonical local `IPSW/` layout and then runs `--preflight`.

## Output Summary

The command reports:

- whether a device was detected
- current device state
- product
- board config
- selected build
- payload source used
- extraction result
- preflight result
- current readiness level
- next recommended command

## Next Steps

If preparation completes cleanly, the usual next safe command is:

```bash
./venv/bin/python odts.py --acquire-shsh
```

If the command reports device detection failure, use:

```bash
./venv/bin/python odts.py --device-state --verbose
```

After successful SHSH acquisition:

```bash
./venv/bin/python odts.py --preflight
```

If you already have a previously acquired valid blob for the same connected device and the same selected build, placing it at `resources/shsh.shsh` also satisfies the current signing-material requirement.

If SHSH cannot be obtained for the selected build, that is currently a real architecture blocker for the legacy T2 path, not just a missing-file nuisance.
