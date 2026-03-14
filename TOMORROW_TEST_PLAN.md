# Tomorrow Test Plan

This checklist is for validating the repository on:

- one host Mac
- one T2 test Mac in DFU mode

The sequence is ordered from safest and most diagnostic to most involved. Stop at the first failing stage and capture the requested logs before moving on.

## 1. Test Setup

## Host Mac prerequisites

- macOS host with admin access
- Python 3.10+ available as `python3` or `python`
- internet access for dependency install and optional remote metadata access
- USB cable known to work with the T2 test Mac
- sufficient free disk space for IPSW extraction
- clone of this repo on the Mac

## T2 test Mac prerequisites

- T2-based target Mac
- ability to place it into DFU mode
- no expectation yet of end-to-end success

## Required repo resources

Confirm these exist before testing:

- `resources/bin/irecovery`
- `resources/bin/img4tool`
- `resources/bin/img4`
- `resources/bin/iBoot64Patcher`
- `resources/bin/Kernel64Patcher`
- `resources/bin/dtree_patcher`
- `resources/bin/ibootim`
- `resources/device_map.txt`
- `resources/018-75901-013.dmg`
- `resources/bootlogo.png`
- `resources/ipwndfu/checkm8.py`
- `resources/ipwndfu8012/ipwndfu`
- `resources/ipwndfu8012/nop_image4.py`

Known blockers to check immediately:

- `resources/bin/tsschecker`
- `resources/ipwndfu8012/checkm8.py`

If either is missing, note that before running live stages.

## Logs to prepare

From the repo root on the host Mac:

```bash
mkdir -p logs
```

Use a dedicated log file for each run:

```bash
python odts.py --diagnostic --json > logs/01-diagnostic.json
```

For command runs that support logging:

```bash
python odts.py ... --log-file logs/<name>.log
```

Also capture:

- terminal stdout/stderr
- `git status --short`
- any generated files under `resources/StagedFiles/`

## 2. Stage A: Host-Only Safe Validation

No device required.

## A1. Verify Python dependencies

Command:

```bash
python -m pip install -r requirements.txt
```

Expected output:

- package install completes without import/build errors

Signs of failure:

- `No module named ...`
- pip build/install failure

Capture:

- full terminal output

Stage failure meaning:

- host Python environment not ready

## A2. Run repository diagnostics

Command:

```bash
python odts.py --diagnostic --json > logs/01-diagnostic.json
```

Expected output:

- JSON report written
- host shown as Darwin
- dependency status populated
- external tools listed

Signs of failure:

- Python traceback
- tool inspection crashes
- missing required repo resources

Capture:

- `logs/01-diagnostic.json`

How to interpret:

- if dependencies are missing: host environment problem
- if binaries are missing: repo/resource problem
- if tools exist but version probing fails: host compatibility problem

## A3. Inspect setup state

Command:

```bash
python odts.py setup > logs/02-setup.txt
python odts.py setup --fetch-missing --dry-run > logs/03-setup-dry-run.txt
```

Expected output:

- list of present/missing repo-local resources
- dry-run fetch plan if supported resources are absent

Signs of failure:

- Python traceback
- unexpected download attempts during dry-run

Capture:

- `logs/02-setup.txt`
- `logs/03-setup-dry-run.txt`

What this validates without end-to-end success:

- bootstrap logic
- repo-local resource inspection

## A4. Validate a manifest directly

Use the bundled sample manifest first.

Command:

```bash
python odts.py --validate-firmware --manifest resources/ipwndfu8012/BuildManifest.plist --board-config j132ap --json > logs/04-validate-sample.json
```

Expected output:

- JSON report with:
  - selected board config
  - stage results
  - artifact plan
  - planned staged outputs
  - planned tool usage

Signs of failure:

- board config not found
- plist parse failure
- missing stage data

Capture:

- `logs/04-validate-sample.json`

What this validates:

- structured manifest parsing
- board-specific component resolution
- non-destructive artifact planning

## A5. Validate a real IPSW non-destructively

If you already have an IPSW for the intended device:

Command:

```bash
python odts.py -q /path/to/restore.ipsw iBridge2,5 --validate-firmware --board-config j132ap --json > logs/05-validate-local-ipsw.json
```

Expected output:

- successful IPSW extraction
- BuildManifest parsed
- board-specific component plan

Signs of failure:

- invalid IPSW archive
- BuildManifest missing
- board config mismatch

Capture:

- `logs/05-validate-local-ipsw.json`

What this validates without device interaction:

- local IPSW handling
- manifest planning against a real restore image

## 3. Stage B: Tool-Level Host Checks

Still non-device or low-risk.

## B1. Check direct binary help/version behavior

Commands:

```bash
./resources/bin/irecovery -h > logs/06-irecovery-help.txt 2>&1
./resources/bin/img4tool -h > logs/07-img4tool-help.txt 2>&1
./resources/bin/img4 -h > logs/08-img4-help.txt 2>&1
```

Expected output:

- help or usage text

Signs of failure:

- macOS blocks execution
- binary is corrupt
- architecture mismatch
- permission denied

Capture:

- the three log files above

Stage failure meaning:

- external binary compatibility problem on the host Mac

## 4. Stage C: Device Detection Only

Requires the T2 Mac in DFU mode.

## C1. Put T2 test Mac into DFU mode

Operator action:

- place the T2 Mac into DFU mode using the standard T2 DFU procedure

Expected result:

- host Mac sees a DFU-capable Apple device

Signs of failure:

- device not detected at all
- device appears in the wrong mode

Capture:

- note exact DFU entry steps used
- cable/port details

## C2. Query device with irecovery

Command:

```bash
./resources/bin/irecovery -q > logs/09-irecovery-query.txt 2>&1
```

Expected output:

- lines including at least:
  - `ECID:`
  - `BDID:`

Signs of failure:

- no device found
- no `ECID`/`BDID`
- permission/USB errors

Capture:

- `logs/09-irecovery-query.txt`

How to tell which stage failed:

- if this fails, stop. The problem is before SHSH, manifest, patching, or boot chain stages.

## C3. Run ODTS diagnostic with device attached

Command:

```bash
python odts.py --diagnostic --json > logs/10-diagnostic-with-device.json
```

Expected output:

- same host/resource report as before
- confirms current tool/resource visibility in the real host environment

What this validates:

- the repo and host environment remain consistent with a device attached

## 5. Stage D: Safe Device-Associated Planning

Requires device in DFU mode but still avoids live low-level actions where possible.

## D1. Dry-run the intended remote workflow

Command:

```bash
python odts.py -i iBridge2,5 6.1 --dry-run --log-file logs/11-remote-dry-run.log
```

Expected output:

- reads `ECID`/`BDID`
- resolves board config
- logs that SHSH/artifact staging/send actions would occur
- does not perform live device mutation

Signs of failure:

- cannot parse `irecovery` output
- board config not found
- missing required binary detected too early

Capture:

- `logs/11-remote-dry-run.log`
- terminal output

What this validates:

- top-level orchestration up to live execution boundary

## D2. Dry-run local IPSW workflow

Command:

```bash
python odts.py -q /path/to/restore.ipsw iBridge2,5 --dry-run --log-file logs/12-local-dry-run.log
```

Expected output:

- local IPSW recognized
- board config resolved from connected device
- logs that staging/send would occur

Signs of failure:

- IPSW mismatch with selected device
- missing `BDID`
- board mapping failure

Capture:

- `logs/12-local-dry-run.log`

## 6. Stage E: Pre-Execution Blocker Check

Before any live attempt, explicitly check missing critical pieces.

## E1. Confirm blocker resources

Commands:

```bash
test -f resources/bin/tsschecker && echo "tsschecker present" || echo "tsschecker missing"
test -f resources/ipwndfu8012/checkm8.py && echo "checkm8 present" || echo "checkm8 missing"
```

Expected output:

- ideally both present

Signs of failure:

- either missing

What this means:

- if `tsschecker` is missing:
  - SHSH acquisition stage will fail
- if `resources/ipwndfu8012/checkm8.py` is missing:
  - some exploit paths will fail

Capture:

- terminal output

## 7. Stage F: Limited Live Execution Attempt

Only proceed if the earlier stages are clean and you accept that this area is still legacy/unverified.

## F1. Pwn-only attempt

Command:

```bash
python odts.py -p --log-file logs/13-pwn-only.log
```

Expected output:

- some exploit branch executes
- logs indicate whether device entered pwned DFU mode

Signs of failure:

- missing exploit resource
- no Apple device found
- exploit branch references missing paths
- Python interpreter mismatch in legacy scripts

Capture:

- `logs/13-pwn-only.log`
- terminal output

How to tell which stage failed:

- if this fails before any output from exploit tooling:
  - wrapper/resource problem
- if exploit tooling starts but device state never changes:
  - exploit/runtime/device problem

## F2. Live remote workflow attempt

Command:

```bash
python odts.py -i iBridge2,5 6.1 --log-file logs/14-live-remote.log
```

Expected output, stage by stage:

1. `irecovery` query succeeds
2. board config resolves
3. SHSH request succeeds
4. manifest/assets are fetched
5. staged files appear under `resources/StagedFiles/`
6. patch/sign steps complete
7. exploit/send sequence begins

Signs of failure:

- no `.shsh2` or `resources/shsh.shsh`
- missing staged files
- tool wrapper error for `tsschecker`, `img4tool`, `img4`, or patchers
- pauses or stops inside `resources/img4.py`
- `irecovery` send failures

Capture:

- `logs/14-live-remote.log`
- terminal output
- listing of `resources/StagedFiles/`

Helpful command after failure:

```bash
find resources/StagedFiles -maxdepth 1 -type f | sort > logs/15-staged-files.txt
```

## F3. Live local IPSW workflow attempt

Command:

```bash
python odts.py -q /path/to/restore.ipsw iBridge2,5 --log-file logs/16-live-local.log
```

Expected output:

- same staged progression as remote mode, but using local IPSW extraction

Signs of failure:

- local IPSW mismatch
- BuildManifest mismatch
- patch/sign failure
- device send failure

Capture:

- `logs/16-live-local.log`
- `logs/15-staged-files.txt` equivalent after run

## 8. Failure Triage Guide

## If diagnostics fail

- Stage failed:
  - host setup / dependency / binary presence

## If `irecovery -q` fails

- Stage failed:
  - device detection / DFU entry / USB connectivity

## If `--validate-firmware` fails

- Stage failed:
  - manifest parsing / board selection / IPSW structure

## If dry-run works but live run fails immediately

- Stage failed:
  - missing external tool or resource

## If SHSH step fails

- Stage failed:
  - `tsschecker` availability or compatibility

## If staging fails after manifest resolution

- Stage failed:
  - `img4tool` / `img4` / patcher invocation
  - missing firmware components

## If staged files exist but boot/send fails

- Stage failed:
  - exploit path
  - `irecovery` send path
  - boot sequence logic

## If boot seems to proceed but no mount appears

- Stage failed:
  - post-boot ramdisk behavior
  - host-side recognition/mounting
  - unimplemented/incomplete later boot stages

## 9. What Can Be Validated Without End-To-End Success

Even if the full chain does not work, you can still validate:

- the host Mac can run the repo’s Python and bundled binaries
- diagnostics work
- setup inspection works
- manifest parsing works
- board-specific component planning works
- local IPSW extraction works
- `irecovery` can query the connected T2 device
- the CLI can reach dry-run/live boundaries with useful error reporting
- staged artifacts are partially generated before failure

That is still valuable because it tells you whether the breakage is:

- host environment
- missing resource
- manifest/planning
- patch/sign tooling
- exploit/device-state transition
- boot/send sequence

## 10. Minimum Artifacts To Keep After Testing

Retain:

- `logs/01-diagnostic.json`
- `logs/04-validate-sample.json`
- `logs/09-irecovery-query.txt`
- the relevant dry-run or live log
- staged file listing after any live attempt
- note of whether `tsschecker` and `resources/ipwndfu8012/checkm8.py` were present

These are enough to identify which stage failed without rerunning everything immediately.
