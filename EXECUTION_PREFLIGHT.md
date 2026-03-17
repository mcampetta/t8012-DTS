# Execution Preflight

## Exact Commands

Use the repo virtualenv for all safe planning and preflight checks:

```bash
./venv/bin/python odts.py --execution-graph
./venv/bin/python odts.py --execution-graph --json
./venv/bin/python odts.py --preflight
./venv/bin/python odts.py --preflight --json
./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout
./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout --extract-planned-payloads
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --extract-planned-payloads
./venv/bin/python odts.py --remote-payload-layout iBridge2,14 --board-config j152fap --build 19P647 --json
```

These commands are non-destructive. They do not send images, enter pwned DFU, or alter the connected device.

## What The Commands Do

`--execution-graph` prints the planned flow for the selected or connected device:

- selected board identity
- manifest-selected firmware components
- expected source path for each component
- expected staged output path
- planned patch/sign/send steps per component
- external tool expected at each step
- step classification:
  - `validated`
  - `legacy`
  - `unverified`

`--preflight` validates the planned flow without executing it:

- checks whether required tools are present and runnable
- shows which binary path was selected for each tool
- checks whether planned component source payloads can be resolved locally
- lists legacy execution-side modules that would be touched
- reports blockers that currently prevent a credible live execution attempt

`--payload-layout` inspects the expected local payload contract for the planned components:

- validates whether a local IPSW archive contains the required manifest-selected files
- validates whether those files already exist under the expected local payload root
- can optionally extract only the planned payload files into a safe local directory
- does not interact with hardware

`--remote-payload-layout` inspects or prepares the same canonical local payload layout from a remote restore IPSW:

- resolves the restore URL from `ipsw.me` metadata
- defaults to the current safe planning build unless `--build` overrides it
- inspects the remote archive with range-based ZIP access
- validates whether the exact manifest-selected files exist remotely
- can optionally extract only the planned payload files into the canonical local `IPSW/` layout
- writes a small cache file at `IPSW/.odts-remote-payload-cache.json`
- falls back cleanly to the existing local IPSW workflow if remote inspection is unavailable

## Current Required Tools

For the `j152fap` connected-device plan, the current preflight expects:

- `irecovery`
- `img4tool`
- `img4`
- `iBoot64Patcher`
- `kairos`
- `Kernel64Patcher`
- `dtree_patcher`

Current host result:

- `irecovery`: selected system binary `/opt/homebrew/bin/irecovery`
- patch/sign tools: selected bundled repo binaries

## Current Required Artifacts

For the currently planned `j152fap` flow:

- `Firmware/dfu/iBEC.j152f.RELEASE.im4p`
- `Firmware/dfu/iBSS.j152f.RELEASE.im4p`
- `kernelcache.release.ibridge2p`
- `Firmware/all_flash/DeviceTree.j152fap.im4p`
- `Firmware/018-77781-055.dmg.trustcache`
- `Firmware/AOP/aopfw-t8012aop.im4p`
- `Firmware/J152f_Multitouch.im4p`
- `resources/018-75901-013.dmg`
- `resources/bootlogo.png`
- `resources/ipwndfu8012/BuildManifest.plist`

## Readiness Layers

The current safe workflow now needs to be read in three separate layers:

- payload readiness
  - planned firmware payloads resolve locally
  - current status: satisfied on this lab host after local or remote extraction
- signing-material readiness
  - `resources/shsh.shsh` exists for the selected connected device and selected build
  - current status: not satisfied
- runtime readiness
  - the legacy Python/libusb runtime boundary is clean enough for controlled execution-adjacent testing
  - current status: not satisfied

## Current Required Signing Material

For live image signing stages, preflight currently expects:

- `resources/shsh.shsh`

This is not payload material.

It is the personalized signing ticket used by `img4tool` when wrapping patched IMG4 payloads.

Acquire it with:

```bash
./venv/bin/python odts.py --acquire-shsh
```

## What Is Currently Validated

- live connected-device identity detection
- wrapper-based binary selection
- preference for runnable system `irecovery`
- manifest parsing and board identity selection
- artifact planning for `j152fap`
- execution-graph rendering
- preflight blocker reporting
- safe SHSH acquisition into `resources/shsh.shsh`

## What Remains Legacy Or Unverified

Legacy:

- `resources/img4.py`
- `resources/pwn.py`
- use of external native patch/sign binaries during live flow

Unverified:

- `resources/ipwndfu8012/ipwndfu`
- `resources/ipwndfu8012/nop_image4.py`
- live send/boot ordering over `irecovery`
- end-to-end boot chain success on target hardware

## Current Live-Execution Blockers

As of the current preflight on this machine, payload resolution is no longer the blocker:

- planned payloads resolve from the canonical local `IPSW/` layout
- required external tools are runnable
- `--preflight` currently reports no unresolved payload blockers

The remaining boundary is execution-side:

- first execution-side step: `enter-pwned-dfu`
- classification: `unverified`
- module: `resources/pwn.py`
- tool entry: `resources/ipwndfu8012/nop_image4.py`

## Payload Sourcing Paths

Operators can now clear payload-material requirements in either safe way:

- local IPSW workflow: `-q /path/to/restore.ipsw iBridge2,14 --payload-layout --extract-planned-payloads`
- remote IPSW workflow: `--remote-payload-layout iBridge2,14 --board-config j152fap --extract-planned-payloads`

Both populate the same canonical local `IPSW/` layout that preflight checks.

Reference:

- `IPSW_SOURCING.md` describes the original legacy sourcing flow and why the current repo still expects either a remote archive extraction path or a local `IPSW/` tree.
- `REMOTE_IPSW_SOURCING.md` documents the safe remote helper, cache file, and fallback behavior.

Important caveat:

- clearing the payload blocker alone does not automatically move the repo to `ready for controlled live step testing`
- the first execution-side step remains `unverified`

## Recommended Next Safe Step

Before any live execution attempt, confirm payloads remain resolved and rerun:

```bash
./venv/bin/python odts.py --preflight
```

The goal is for preflight to show:

- all required source payloads resolved
- all required tools runnable
- no unresolved blockers
- a remaining decision boundary only around explicitly accepted legacy/unverified execution risk
