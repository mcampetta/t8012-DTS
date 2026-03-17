# Host Bootstrap

## Scope

This document covers host-only setup for another lab Mac.

It does not execute the legacy pwn chain.

It does not interact with hardware.

## Supported Host Assumptions

- macOS host
- Homebrew can be installed or is already available
- network access is available for Homebrew, `pyenv`, and Python package installation
- the repository is already checked out locally
- the operator can run shell commands in the repo root

## Admin / Setup Workflow

Run:

```bash
./scripts/bootstrap_lab_mac.sh
```

The bootstrap script is designed to be idempotent where practical. It will:

- verify macOS and host architecture
- verify or install Homebrew
- verify or install required Homebrew packages:
  - `pyenv`
  - `libusb`
  - `libirecovery`
  - `readline`
  - `xz`
  - `pkg-config`
- verify or install Python `2.7.18` through `pyenv`
- treat OpenSSL as a build-time helper dependency only:
  - skip OpenSSL entirely if Python `2.7.18` is already installed and usable
  - reuse an existing Homebrew OpenSSL if one is already present
  - install `openssl@3` only when a fresh Python `2.7.18` build needs it
- persist the selected legacy interpreter export to:
  - `.odts-legacy-python.env`
- create or update the repo `venv`
- install Python 3 dependencies from `requirements.txt`
- install Python 2-side dependency `pyusb==1.0.2`
- verify Homebrew `libusb`
- run non-destructive validation commands:
  - `./venv/bin/python odts.py --check-legacy-pwn-runtime --json`
  - `./venv/bin/python odts.py --preflight --board-config j152fap --json`
  - validate that both JSON output files are present, non-empty, and parseable before printing the final summary

## Operator / Runtime Workflow

After bootstrap completes:

```bash
source ./.odts-legacy-python.env
./venv/bin/python odts.py --check-legacy-pwn-runtime
./venv/bin/python odts.py --preflight
```

If payload material is not already prepared on that host, continue with one of:

```bash
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --extract-planned-payloads
./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout --extract-planned-payloads
./venv/bin/python odts.py --preflight
```

## Manual Steps Still Required

- review whether Homebrew installation is allowed on the target lab Mac
- `source ./.odts-legacy-python.env` in any shell that will run runtime checks or previews
- provide local or remote payload material if `--preflight` still reports payload blockers
- review the remaining runtime packaging issue before any future live-step work:
  - `vendored_libusbfinder_ready=False`

## OpenSSL Behavior

The bootstrap script no longer assumes `openssl@1.1` exists in Homebrew.

Current behavior:

- if Python `2.7.18` is already installed and usable:
  - OpenSSL is skipped because it is not needed for that rerun
- if Python `2.7.18` must be built and a Homebrew OpenSSL is already installed:
  - that existing formula is reused
- if Python `2.7.18` must be built and no Homebrew OpenSSL is present:
  - `openssl@3` is installed as a build dependency

The script logs one of these outcomes explicitly:

- `OpenSSL status: skipped because not needed`
- `OpenSSL status: already satisfied via ...`
- `OpenSSL status: installing ... as a build dependency`

## JSON Capture Behavior

Bootstrap validation commands now capture JSON on stdout only.

Operational logs are written to stderr, and the bootstrap summary step validates both JSON files before parsing them.

If a captured file is missing, empty, or invalid JSON, the script will:

- print a clear diagnostic
- show the first few lines of the bad file when available
- exit cleanly instead of crashing in the summary step

## Ready Machine Criteria

A host is ready for the current planning-and-preview scope when:

- `interpreter_ready=True`
- `module_import_ready=True`
- `libusb_backend_ready=True`
- `./venv/bin/python odts.py --preflight` reports no blockers

The host is only `preview-clean` for the declared legacy runtime contract when:

- `preview_clean_runtime_boundary=True`

That stricter state still does not authorize execution. It only means the host-side runtime boundary is explicit and clean enough for future controlled test planning.

## Current Known Gap

The current lab model expects:

- `interpreter_ready=True`
- `module_import_ready=False`
- `libusb_backend_ready=False`
- `vendored_libusbfinder_ready=False`

That means bootstrap can make host setup reproducible, but it does not yet clear the remaining vendored packaging/import boundary automatically.

## Troubleshooting

If bootstrap fails:

- Homebrew missing after install attempt:
  - verify `/opt/homebrew/bin/brew` or `/usr/local/bin/brew`
- Python 2.7 build failure:
  - re-run the script after confirming the required brew libraries installed cleanly
  - check the OpenSSL log line to confirm whether the build reused an existing formula or installed `openssl@3`
- `ODTS_LEGACY_PYTHON` not visible in a later shell:
  - run `source ./.odts-legacy-python.env`
- `missing_pyusb`:
  - re-run `./scripts/bootstrap_lab_mac.sh`
- `missing_libusb`:
  - verify `brew list --versions libusb`
- `libusbfinder_packaging_issue`:
  - this is an expected remaining boundary until the vendored USB packaging assumption is addressed explicitly

## Validation Commands

Use these commands to verify another machine:

```bash
source ./.odts-legacy-python.env
./venv/bin/python odts.py --check-legacy-pwn-runtime
./venv/bin/python odts.py --check-legacy-pwn-runtime --json
./venv/bin/python odts.py --preflight
./venv/bin/python odts.py --preflight --json
```
