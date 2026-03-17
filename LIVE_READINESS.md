# Live Readiness

## Current Readiness Level

`ready for planning only`

Rationale:

- connected-device detection is working on real hardware
- board identity and firmware planning are coherent for `j152fap`
- required patch/sign/query tools are currently runnable
- planned firmware payload sources now resolve from the canonical local `IPSW/` layout
- local and remote payload sourcing helpers are both available for repeatable preparation
- the first execution-side step still routes through legacy and unverified code

## Current Blockers

There are no remaining payload-resolution blockers in the current preflight result.

The remaining blocker is execution-side uncertainty:

- first execution-side step: `enter-pwned-dfu`
- classification: `unverified`
- module: `resources/pwn.py`
- tool entry: `resources/ipwndfu8012/nop_image4.py`

Current preview finding:

- `resources/ipwndfu8012/ipwndfu` requires missing interpreter `/usr/bin/python`
- `resources/pwn.py` invokes `nop_image4.py` via bare `python`, which is also absent on this host
- transitive helper modules under `resources/ipwndfu8012` still contain Python 2 syntax

Current runtime-audit finding:

- the blocker chain is primarily runtime compatibility, not current device behavior
- direct runtime blockers:
  - `interpreter_missing`
  - `path_assumption`
  - `python2_syntax_dependency`
  - `macOS runtime assumption`
- broader transitive chain reaches legacy helper modules including:
  - `checkm8.py`
  - `dfuexec.py`
  - `libusbfinder/__init__.py`
  - vendored `usb/...` modules

Traceability:

- see `MISSING_PAYLOADS.md` for per-component source paths, derivation, expected source kind, module ownership, and proposed non-destructive remediation
- see `IPSW_SOURCING.md` for the original legacy firmware sourcing flow and the exact local `IPSW/` layout expected by the old local-IPSW path
- see `REMOTE_IPSW_SOURCING.md` for the safe remote metadata lookup, archive inspection, selective extraction path, and cache file
- see `ENTER_PWNED_DFU_ANALYSIS.md` for the current call graph, command preview, interpreter assumptions, and modern-macOS failure points
- see `PWN_RUNTIME_AUDIT.md` for the full legacy runtime compatibility chain and blocker classification

## First Execution-Side Step

After planning, the first execution-side step would be:

- `enter-pwned-dfu`
- tool path/entry: `ipwndfu8012/nop_image4.py`
- module: `resources/pwn.py`

Current classification:

- `unverified`

Reason:

- the entry point exists
- it is part of legacy execution-side code
- it has not yet been validated in this lab pass
- preflight blockers remain before a controlled live attempt should be made

Why it is not yet a safe live candidate:

- the entry point lives in legacy execution code
- the payload contract is now clear, but the entry point itself remains unvalidated in this lab pass
- the runtime compatibility chain fails before exploit behavior can be meaningfully observed on this host
- a controlled live attempt would still begin from an execution-side step with no live observability validation yet

## First Safe Live Test Candidate

No safe live test candidate is recommended yet.

The first candidate should only be reconsidered after:

- all planned firmware payload sources remain resolved locally
- `./venv/bin/python odts.py --preflight` reports no unresolved blockers
- `./venv/bin/python odts.py --preview-enter-pwned-dfu` reports a credible launcher and interpreter contract
- the operator is ready to capture full logs and stop immediately on unexpected behavior

Would a valid local IPSW/extraction clear the current blocker?

- payload-material blockers are already cleared on this machine
- a valid local IPSW or remote selective extraction is sufficient to recreate that prepared state
- no, payload availability alone does not prove readiness for controlled live step testing
- no, solving the runtime compatibility blockers alone would still not prove device-side behavior
- the repo still needs an explicit decision on whether the `enter-pwned-dfu` step is sufficiently instrumented and observable to advance beyond planning-only status

## Exact Logs To Capture

Before any live attempt, capture:

```bash
./venv/bin/python odts.py --device-state --verbose
./venv/bin/python odts.py --execution-graph --json
./venv/bin/python odts.py --preflight --json
./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout --json
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --json
./venv/bin/python odts.py --preview-enter-pwned-dfu --json
```

If a future controlled live step is attempted, also capture:

- full terminal stdout/stderr
- `--log-file` output from the ODTS entry command
- exact selected tool paths from diagnostics/preflight
- device mode before and after the attempted step
- any USB disconnect/reconnect timing observed on the host

## Stop Conditions

Stop immediately if any of the following occur:

- unexpected device disconnect or unplanned mode transition
- `--preflight` stops resolving planned payloads
- `--preview-enter-pwned-dfu` reports missing interpreter or Python 2 compatibility blockers
- `--audit-enter-pwned-dfu-runtime` reports unresolved runtime compatibility blockers
- selected tool reports loader/runtime failure
- legacy execution code prompts for interactive retry or blocks unexpectedly
- observed behavior differs from the declared first-step expectation
- preflight output changes in a way that removes previously selected runnable tools

## Commands To Recheck Readiness

```bash
./venv/bin/python odts.py --execution-graph
./venv/bin/python odts.py --preflight
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap
./venv/bin/python odts.py --preview-enter-pwned-dfu
```

Only consider moving to controlled live-step testing after the readiness level changes to:

- `ready for controlled live step testing`
