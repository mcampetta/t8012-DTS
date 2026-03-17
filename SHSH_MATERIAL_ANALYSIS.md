# SHSH Material Analysis

## Summary

The remaining preflight blocker:

- `signing material missing: resources/shsh.shsh is not present`

is not a payload-sourcing problem.

It is a signing-material readiness problem.

For the current T2 implementation, it is also an architecture problem when the blob cannot be obtained, because the pipeline is hybrid by design and still functionally SHSH-dependent overall.

## Where The File Is Referenced

Primary current references:

- [odtslib/config.py](/Users/kocrrd/Documents/t8012-DTS/odtslib/config.py)
  - defines `SHSH_PATH = resources/shsh.shsh`
- [odts.py](/Users/kocrrd/Documents/t8012-DTS/odts.py)
  - `find_generated_shsh()` looks for a generated `.shsh2` in the repo root
  - `sign_iboot_images()` passes `SHSH_PATH` into `img4tool`
  - `run_remote_flow()` invokes `tsschecker`, then moves the generated `.shsh2` to `resources/shsh.shsh`
- [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py)
  - `signImages()` signs multiple IMG4 payloads using `resources/shsh.shsh`
  - `img4stuff()` obtains SHSH by calling `TOOLS.tsschecker.request_shsh(...)`
  - then moves the generated `.shsh2` file into `./resources/shsh.shsh`
- [odtslib/execution_preflight.py](/Users/kocrrd/Documents/t8012-DTS/odtslib/execution_preflight.py)
  - treats missing `resources/shsh.shsh` as a live-execution blocker

## Which Module Expects It

The main consumer is:

- [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py)

Supporting consumers:

- [odts.py](/Users/kocrrd/Documents/t8012-DTS/odts.py)
  - wrapper-level signing for `ibss` / `ibec`
- [odtslib/tool_wrappers.py](/Users/kocrrd/Documents/t8012-DTS/odtslib/tool_wrappers.py)
  - `Img4Tool.sign_img4(..., shsh_path=...)`

## Role / Format

Legacy ODTS treats `resources/shsh.shsh` as the signing input passed to `img4tool -s`.

In practice, the old code flow was:

1. run `tsschecker`
2. generate a `.shsh2` ticket in the current working directory
3. move that file to `resources/shsh.shsh`
4. pass it to `img4tool` as the signing ticket for IMG4 wrapping

So the repo-local filename is a normalized path contract, not the original produced extension.

## How The Old Tool Originally Obtained It

Legacy automatic generation path:

- [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py)
  - prints `Getting SHSH for signing images`
  - reads live `ECID` from the connected device via `dfu.acquire_device()`
  - calls `TOOLS.tsschecker.request_shsh(device_model=deviceModel, ecid=ecid, ios_version=iOSVersion)`
  - scans the current working directory for `*.shsh2`
  - moves the generated file to `./resources/shsh.shsh`

Modernized wrapper path:

- [odts.py](/Users/kocrrd/Documents/t8012-DTS/odts.py)
  - in `run_remote_flow()`, calls `tools.tsschecker.request_shsh(...)`
  - then moves the generated ticket to `SHSH_PATH`

## Original Acquisition Logic

`tsschecker` was the intended acquisition mechanism.

Inputs used by the current modernized wrapper:

- device model
- ECID
- iOS version

That means the signing material is at least:

- device-specific
- build/version-specific

The original architecture notes also describe Stage 4 as:

- request a personalized signing ticket
- produce `.shsh2`
- move it to `resources/shsh.shsh`

## Specificity

Based on the current and legacy call sites, the ticket should be treated as:

- device-specific: yes, because ECID is required
- build-specific: yes, because `tsschecker` is invoked against a selected OS/build target
- board-specific: indirectly, because the selected firmware plan and image set depend on board identity, but the ticket request itself is keyed primarily by device model + ECID + selected firmware target

## Why It Is Missing In The Current Safe Flow

The current missing file is most consistent with:

- removed legacy generation logic from the safe planning/preflight path
- missing external tool integration in the safe non-destructive workflow
- manual operator/admin step not yet surfaced clearly

It is not primarily:

- a payload path mismatch
- a stale `resources/shsh.shsh` path assumption

The path itself is consistent across legacy and modernized code.

## Is Preflight Correct To Require It This Early

For payload readiness:

- no

For live execution readiness:

- yes

Reason:

- payload sourcing and planning can be validated without SHSH material
- actual IMG4 signing cannot proceed without the ticket
- the current preflight is acting as execution-readiness preflight, not payload-only preflight

So the current blocker is legitimate, but it should be documented more precisely as:

- `signing-material readiness` blocker

not as a payload blocker.

It should also be treated as:

- a real architecture blocker when SHSH for the selected device/build cannot be acquired

## Exact Current Operator/Admin Action

Current operator/admin action is not “provide a payload file”.

It is:

1. acquire valid signing material for the selected connected device and selected build
2. normalize the resulting ticket to `resources/shsh.shsh`
3. re-run:

```bash
./venv/bin/python odts.py --acquire-shsh
./venv/bin/python odts.py --preflight
```

Optional explicit build selection:

```bash
./venv/bin/python odts.py --acquire-shsh --build 19P647
```

If an operator/admin already has a previously acquired valid blob for the same device and selected build, that blob can satisfy the current requirement when placed at `resources/shsh.shsh`.

This is only valid when the blob matches:

- the connected device
- the selected build

It should not be treated as a generic reusable file across unrelated devices or builds.

## Safe Automation Target

The safe automation target is:

- a dedicated non-destructive SHSH acquisition helper that:
  - reads connected device identifiers safely
  - resolves the selected build
  - invokes `tsschecker` without entering the exploit/device-execution path
  - persists the resulting ticket to `resources/shsh.shsh`

That would be host-side and network/tool driven, not exploit driven.

This helper now exists:

```bash
./venv/bin/python odts.py --acquire-shsh
./venv/bin/python odts.py --acquire-shsh --build 19P647
./venv/bin/python odts.py --acquire-shsh --json
```

See also:

- `SHSH_ACQUISITION_GAP_ANALYSIS.md`
  - current invocation
  - legacy invocation
  - identity-selection mismatch
  - current argument-parity fix

## Current Conclusion

The repo is now:

- payload-ready
- not signing-material-ready
- not runtime-ready for the legacy execution boundary

The remaining blocker is precise and actionable:

- obtain or safely automate acquisition of `resources/shsh.shsh` for the connected device and selected build

If that acquisition is impossible for the selected device/build, the blocker is not just operational. It is an architecture blocker for the current hybrid T2 implementation.
