# Live Readiness

## Current Readiness Level

`ready for planning only`

Rationale:

- connected-device detection is working on real hardware
- board identity and firmware planning are coherent for `j152fap`
- required patch/sign/query tools are currently runnable
- planned firmware payload sources now resolve from the canonical local `IPSW/` layout
- local and remote payload sourcing helpers are both available for repeatable preparation
- the current T2 path is hybrid by design:
  - pwned-DFU / `nop_image4.py` is used to relax Image4 handling
  - SHSH-backed IMG4 signing is still used for most of the boot chain
- signing material is still missing at `resources/shsh.shsh`
- the first execution-side step still routes through legacy and unverified code

## Current Blockers

There are no remaining payload-resolution blockers in the current preflight result.

The remaining blockers are now split across two different readiness layers:

- signing-material readiness:
  - `resources/shsh.shsh` is not present
  - SHSH is still functionally required in the current implementation overall
  - safe operator action now exists:
    - `./venv/bin/python odts.py --acquire-shsh`
  - inability to obtain a valid blob for `iBridge2,14` / `19P647` is a real architecture blocker, not just a missing-file problem
- runtime readiness:
  - legacy pwn/runtime boundary still not preview-clean
- execution readiness:
  - still blocked because the current pipeline depends on both the SHSH-backed signing path and the unverified pwned-DFU/Image4-bypass path

Execution-side uncertainty remains:

- first execution-side step: `enter-pwned-dfu`
- classification: `unverified`
- module: `resources/pwn.py`
- tool entry: `resources/ipwndfu8012/nop_image4.py`

Current preview finding:

- host shim cleanup is in place:
  - `resources/ipwndfu8012/ipwndfu` now declares `#!/usr/bin/env python2`
  - `resources/pwn.py` now launches the T8012 chain through an explicit legacy-runtime contract
- current remaining preview blockers:
  - no explicit legacy Python 2 interpreter is currently selected
  - vendored `libusbfinder` packaging assumptions are not clean for this macOS host
- transitive helper modules under `resources/ipwndfu8012` still contain Python 2 syntax, but that is now tracked as part of the declared legacy runtime contract rather than as an implicit launcher failure

Current runtime-audit finding:

- the blocker chain is primarily runtime compatibility, not current device behavior
- direct runtime blockers:
  - `interpreter_missing`
  - `external_dependency_packaging_issue`
- broader transitive chain reaches legacy helper modules including:
  - `checkm8.py`
  - `dfuexec.py`
  - `libusbfinder/__init__.py`
  - vendored `usb/...` modules

Current runtime-check finding:

- `preview_clean_runtime_boundary=False`
- active host-side issues on this machine:
  - `missing_pyusb`
  - `missing_libusb`
  - `libusbfinder_packaging_issue`
- selected host-side interpreter state:
  - `interpreter_ready=True`
  - `module_import_ready=False`
  - `libusb_backend_ready=False`
  - `vendored_libusbfinder_ready=False`
- host bootstrap support now exists:
  - `./scripts/bootstrap_lab_mac.sh`
- runtime checker now separates:
  - `interpreter_ready`
  - `module_import_ready`
  - `libusb_backend_ready`
  - `vendored_libusbfinder_ready`
  - `preview_clean_runtime_boundary`

Traceability:

- see `OPERATOR_WORKFLOW.md` for the single-command operator preparation flow
- see `SHSH_ACQUISITION_GAP_ANALYSIS.md` for the bridgeOS/T2 `tsschecker` identity-selection mismatch and the current argument-parity fix
- see `SHSH_MATERIAL_ANALYSIS.md` for the signing-material contract, original acquisition flow, and current operator/admin action
- see `MISSING_PAYLOADS.md` for per-component source paths, derivation, expected source kind, module ownership, and proposed non-destructive remediation
- see `IPSW_SOURCING.md` for the original legacy firmware sourcing flow and the exact local `IPSW/` layout expected by the old local-IPSW path
- see `REMOTE_IPSW_SOURCING.md` for the safe remote metadata lookup, archive inspection, selective extraction path, and cache file
- see `ENTER_PWNED_DFU_ANALYSIS.md` for the current call graph, command preview, interpreter assumptions, and modern-macOS failure points
- see `PWN_RUNTIME_AUDIT.md` for the full legacy runtime compatibility chain and blocker classification
- see `ENTER_PWNED_DFU_REMEDIATION_PLAN.md` for the safe modernization triage plan and recommended order of operations
- see `LEGACY_PWN_RUNTIME_CONTRACT.md` for the declared interpreter/runtime contract for the legacy T8012 chain
- see `LEGACY_PWN_RUNTIME_SETUP.md` for the smallest host-side setup steps and export guidance
- see `HOST_BOOTSTRAP.md` for reproducible lab-machine setup and validation flow

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

Current remediation triage:

- host shim only:
  - `resources/ipwndfu8012/ipwndfu`
  - `resources/pwn.py`
- external dependency packaging issue:
  - `resources/ipwndfu8012/libusbfinder/__init__.py`
- low-risk Python 3 port candidate:
  - `resources/ipwndfu8012/utilities.py`
- moderate-risk port candidates:
  - `resources/ipwndfu8012/dfu.py`
  - `resources/ipwndfu8012/alloc8.py`
  - `resources/ipwndfu8012/recovery.py`
- high-risk behavior-sensitive files:
  - `resources/ipwndfu8012/usbexec.py`
  - `resources/ipwndfu8012/checkm8.py`
  - `resources/ipwndfu8012/dfuexec.py`
  - `resources/ipwndfu8012/limera1n.py`
  - `resources/ipwndfu8012/SHAtter.py`
  - `resources/ipwndfu8012/steaks4uce.py`

## First Safe Live Test Candidate

No safe live test candidate is recommended yet.

The first candidate should only be reconsidered after:

- all planned firmware payload sources remain resolved locally
- `./venv/bin/python odts.py --preflight` reports no unresolved blockers
- `./venv/bin/python odts.py --preview-enter-pwned-dfu` reports a credible launcher and interpreter contract
- `./venv/bin/python odts.py --audit-enter-pwned-dfu-runtime` reports no unresolved runtime-compatibility blockers in the chosen scope
- `./venv/bin/python odts.py --check-legacy-pwn-runtime` reports `preview_clean_runtime_boundary=True`
- the operator is ready to capture full logs and stop immediately on unexpected behavior

Would a valid local IPSW/extraction clear the current blocker?

- payload-material blockers are already cleared on this machine
- a valid local IPSW or remote selective extraction is sufficient to recreate that prepared state
- no, payload availability alone does not prove readiness for controlled live step testing
- no, payload availability alone does not satisfy signing-material readiness
- yes, an already valid previously acquired blob can satisfy the current signing-material requirement if it matches the same connected device and selected build
- no, solving the runtime compatibility blockers alone would still not prove device-side behavior
- the repo still needs an explicit decision on whether the `enter-pwned-dfu` step is sufficiently instrumented and observable to advance beyond planning-only status

## Exact Logs To Capture

Before any live attempt, capture:

```bash
./venv/bin/python odts.py --device-state --verbose
./venv/bin/python odts.py --acquire-shsh --json
./venv/bin/python odts.py --execution-graph --json
./venv/bin/python odts.py --preflight --json
./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout --json
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --json
./venv/bin/python odts.py --preview-enter-pwned-dfu --json
./venv/bin/python odts.py --check-legacy-pwn-runtime --json
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
- `--preview-enter-pwned-dfu` or `--audit-enter-pwned-dfu-runtime` reports `Preview-Clean Runtime Boundary: False`
- `--check-legacy-pwn-runtime` reports unresolved host-side runtime issues
- selected tool reports loader/runtime failure
- legacy execution code prompts for interactive retry or blocks unexpectedly
- observed behavior differs from the declared first-step expectation
- preflight output changes in a way that removes previously selected runnable tools

## Commands To Recheck Readiness

```bash
./venv/bin/python odts.py --prepare-device
./venv/bin/python odts.py --acquire-shsh
./venv/bin/python odts.py --execution-graph
./venv/bin/python odts.py --preflight
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap
./venv/bin/python odts.py --preview-enter-pwned-dfu
```

Only consider moving to controlled live-step testing after the readiness level changes to:

- `ready for controlled live step testing`
