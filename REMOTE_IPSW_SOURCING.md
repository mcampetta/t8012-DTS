# Remote IPSW Sourcing

## Purpose

`--remote-payload-layout` is a non-destructive helper for sourcing only the planned firmware payloads needed for preflight from a remote restore IPSW.

It does not:

- interact with hardware
- enter pwned DFU
- send images to the device
- modify exploit or execution-side behavior

## Metadata Source

The helper follows the legacy remote sourcing model:

- metadata source: `https://api.ipsw.me/v4/device/{device}?type=ipsw`
- archive source: the Apple restore IPSW URL returned by `ipsw.me`
- archive access method: `RemoteZip` range-based remote ZIP inspection

This mirrors the legacy `ipswapi.py` / `img4.py` flow, but keeps the result inside the canonical local `IPSW/` layout used by preflight instead of directly staging into `resources/StagedFiles/`.

## Commands

Inspect the restore matching the current planning build for a product identifier:

```bash
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap
```

Inspect a specific build:

```bash
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --build 19P647
```

Inspect as JSON:

```bash
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --json
```

Extract only the planned payloads into the canonical local `IPSW/` tree:

```bash
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --extract-planned-payloads
```

Use a custom local destination root:

```bash
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --extract-planned-payloads --payload-root /tmp/odts-ipsw
```

## What It Reports

The helper reports:

- selected product identifier
- selected build and version
- resolved remote restore URL
- whether range-based remote ZIP inspection succeeded
- whether each manifest-selected payload exists remotely
- whether each local destination path was reused, skipped, or extracted
- the next command to run: `./venv/bin/python odts.py --preflight`

Default build-selection behavior:

- if `--build` is provided, that build is used
- otherwise the helper follows the current safe planning manifest build when one is available
- if no planning manifest build can be resolved, it falls back to the latest signed restore returned by `ipsw.me`

## Cache File

Each successful remote inspection writes a small cache file under the destination root:

- `IPSW/.odts-remote-payload-cache.json`

The cache records:

- resolved product identifier
- selected build
- selected version
- resolved restore URL
- board config used for planning
- whether remote inspection succeeded
- whether range access worked
- extracted payload list for that run

This is for repeatability and operator traceability only. It is not used to drive execution.

## Fallback Behavior

If remote metadata lookup fails, remote ZIP range requests fail, or the archive cannot be inspected safely, the helper reports:

- the resolved restore URL if available
- the failure classification
- the reason
- the fallback command to use the existing local IPSW workflow

Fallback path:

```bash
./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout
```

## When To Use Local IPSW Instead

Prefer the local IPSW workflow when:

- remote range access is blocked by network policy or server behavior
- you already have the exact restore IPSW locally
- you need repeatable offline lab preparation
- you want to inspect or extract from a known archive snapshot without relying on live metadata

## Current Safe Result

Validated on this machine:

- metadata lookup from `ipsw.me` works
- remote URL resolution works
- range-based archive inspection works
- the helper can confirm whether planned `j152fap` payloads exist in the remote archive
- selective remote extraction into a throwaway payload root works for the planned `19P647` files
- the helper writes `IPSW/.odts-remote-payload-cache.json`

Current next step after remote inspection or extraction:

```bash
./venv/bin/python odts.py --preflight
```
