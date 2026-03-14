# Runbook

## Setup

1. Use a Mac for real execution. Windows is suitable only for code inspection, documentation, and limited static checks.
2. Create a Python 3 virtual environment if desired.
3. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## First Commands To Run

Inspect setup state:

```bash
python odts.py setup
```

Fetch supported missing repo-local resources:

```bash
python odts.py setup --fetch-missing
```

Diagnostic only:

```bash
python odts.py --diagnostic --json
```

Dry-run remote flow:

```bash
python odts.py -i iBridge2,5 6.1 --dry-run
```

Dry-run local IPSW flow:

```bash
python odts.py -q /path/to/restore.ipsw iBridge2,5 --dry-run
```

## Operational Notes

- `--dry-run` must not touch the device or perform destructive actions.
- `setup --fetch-missing` is the explicit bootstrap path for supported repo-local resources only.
- setup currently supports repo-local fetches for pinned legacy payload archives such as Fugu and the bundled `img4tool` binary.
- setup intentionally does not run Homebrew, install Python packages, write into `/usr/local`, or disable security settings.
- `--fix` is intentionally removed as an operational repair path.
- The tool still depends on legacy bundled exploit/tool payloads for real boot actions.
- If Defender or another AV quarantines `resources/bin/*`, restore the file before trying to execute on the target Mac checkout.

## Manual Validation Checklist

- Confirm `resources/bin/irecovery` runs on the Mac.
- Confirm `pyusb` can enumerate the device.
- Confirm `resources/ipwndfu8012/ipwndfu` and `resources/ipwndfu8012/nop_image4.py` are usable with the Mac’s Python environment.
- Confirm SHSH generation succeeds via bundled `tsschecker`.
- Confirm IMG4 staging artifacts are created under `resources/StagedFiles/`.
- Confirm the boot flow no longer stops unexpectedly mid-process.

## Known Breakpoints

- legacy Python 2 scripts inside vendored exploit trees
- shell-heavy logic in `resources/img4.py`
- missing or quarantined bundled binaries
- host mismatch: operational flows require macOS

## Safe Troubleshooting

- Start with `--diagnostic`
- Then use `--dry-run`
- Only then attempt real device interaction on the Mac
- If a command fails, capture the exact stderr and the active log level output for follow-up
