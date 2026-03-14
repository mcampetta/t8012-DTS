# Lab Test Commands

This file lists the exact commands to run on the host Mac when testing against a T2 Mac in DFU mode.

Assumptions:

- current working directory is the repo root
- the host Mac has Python 3 installed
- the T2 Mac can be placed into DFU mode

## 1. Environment Validation

## Install Python dependencies

```bash
python -m pip install -r requirements.txt
```

Expected output:

- pip completes successfully
- no import/build errors

Common failure signals:

- `No module named ...`
- build/install failure from pip

## Run diagnostics

```bash
python odts.py --diagnostic --json
```

Expected output:

- JSON object
- host platform reported as `Darwin`
- dependency statuses listed
- external tools listed with presence/runnability

Common failure signals:

- Python traceback
- missing required repo resources
- tool inspection errors

## Inspect setup state

```bash
python odts.py setup
python odts.py setup --fetch-missing --dry-run
```

Expected output:

- present/missing resource report
- dry-run fetch plan only

Common failure signals:

- unexpected live download attempt during dry-run
- Python traceback

## 2. Firmware Validation (`--validate-firmware`)

## Validate bundled sample manifest

```bash
python odts.py --validate-firmware --manifest resources/ipwndfu8012/BuildManifest.plist --board-config j132ap --json
```

Expected output:

- JSON report with:
  - `artifact_plan`
  - `stages`
  - selected `board_config`
  - planned components and staged outputs

Common failure signals:

- plist parse failure
- `No BuildIdentity found`
- missing board config

## Validate a local IPSW non-destructively

```bash
python odts.py -q /path/to/restore.ipsw iBridge2,5 --validate-firmware --board-config j132ap --json
```

Expected output:

- IPSW extracted
- `BuildManifest.plist` parsed
- board-specific artifact plan produced

Common failure signals:

- invalid zip/IPSW
- missing `BuildManifest.plist`
- board config mismatch

## 3. Dependency Checks

## Check direct binary help output

```bash
./resources/bin/irecovery -h
./resources/bin/img4tool -h
./resources/bin/img4 -h
```

Expected output:

- usage/help text from each binary

Common failure signals:

- `Permission denied`
- binary will not execute
- architecture mismatch
- macOS security block

## Check critical missing blockers

```bash
test -f resources/bin/tsschecker && echo "tsschecker present" || echo "tsschecker missing"
test -f resources/ipwndfu8012/checkm8.py && echo "checkm8 present" || echo "checkm8 missing"
```

Expected output:

- ideally both `present`

Common failure signals:

- either prints `missing`

Meaning:

- missing `tsschecker` blocks SHSH retrieval
- missing `checkm8.py` blocks parts of the exploit path

## 4. Device Detection

Place the T2 Mac in DFU mode before running the following.

## Inspect device state first

```bash
python odts.py --device-state
python odts.py --device-state --json
python odts.py --device-state --verbose
```

Expected output:

- one of:
  - `identifiers_ready`
  - `identifiers_partial`
  - `no_device`
  - `tool_comm_failure`
- human-readable mode explains:
  - detected state
  - evidence used
  - identifiers found
  - likely next step

Common failure signals:

- `tool_comm_failure`
  - on Windows/non-Mac this is expected because the bundled `irecovery` binary is Mach-O
  - on the host Mac this usually means `irecovery` could not execute or communicate
- `no_device`
  - no relevant device could be observed

What this validates:

- whether the host can safely inspect the attached device before deeper workflow steps

## Query device with irecovery

```bash
./resources/bin/irecovery -q
```

Expected output:

- device information including at least:
  - `ECID:`
  - `BDID:`

Common failure signals:

- no device detected
- no `ECID` / `BDID`
- USB or permission error

## Run diagnostics with device attached

```bash
python odts.py --diagnostic --json
```

Expected output:

- same diagnostic object as before
- confirms repo/tool state while device is attached

Common failure signals:

- same as environment validation

## Dry-run remote workflow using connected device

```bash
python odts.py -i iBridge2,5 6.1 --dry-run --log-file logs/remote-dry-run.log
```

Expected output:

- `ECID` / `BDID` parsed
- board config resolved
- log indicates SHSH/staging/send would occur

Common failure signals:

- cannot parse `irecovery -q`
- board config not found
- missing binary/resource reported

## Dry-run local IPSW workflow using connected device

```bash
python odts.py -q /path/to/restore.ipsw iBridge2,5 --dry-run --log-file logs/local-dry-run.log
```

Expected output:

- local IPSW accepted
- board config resolved from device
- dry-run message indicates staging/send would occur

Common failure signals:

- IPSW mismatch
- missing `BDID`
- board map failure

## 5. Stage-by-Stage Diagnostics

Use these commands to isolate where the pipeline breaks.

## Stage A: host and repo only

```bash
python odts.py --diagnostic --json
python odts.py setup
python odts.py --validate-firmware --manifest resources/ipwndfu8012/BuildManifest.plist --board-config j132ap --json
```

Validates:

- host environment
- repo resources
- manifest parsing
- planning layer

## Stage B: connected device only

```bash
python odts.py --device-state
./resources/bin/irecovery -q
python odts.py -i iBridge2,5 6.1 --dry-run
```

Validates:

- non-destructive state classification
- DFU device visibility
- top-level device query/orchestration

## Stage C: SHSH boundary

```bash
test -f resources/bin/tsschecker && echo "tsschecker present" || echo "tsschecker missing"
```

Validates:

- whether live SHSH stage is even possible

## Stage D: live pwn boundary

```bash
python odts.py -p --log-file logs/pwn-only.log
```

Expected output:

- exploit branch runs
- success/failure message about pwned DFU

Common failure signals:

- missing exploit resource
- interpreter mismatch
- device never enters pwned state

## Stage E: live remote flow

```bash
python odts.py -i iBridge2,5 6.1 --log-file logs/live-remote.log
```

Expected output by stage:

- device query succeeds
- board config resolves
- SHSH retrieval succeeds
- staged files appear
- patch/sign phase begins
- boot/send phase begins

Common failure signals:

- no `.shsh2` created
- no `resources/shsh.shsh`
- `img4tool`/patcher errors
- missing staged outputs
- exploit/send failure

## Stage F: live local IPSW flow

```bash
python odts.py -q /path/to/restore.ipsw iBridge2,5 --log-file logs/live-local.log
```

Expected output:

- local IPSW accepted
- same staging/sign/send progression as remote mode

Common failure signals:

- local IPSW mismatch
- missing artifacts
- patch/sign/send failure

## Interpreting Failures

- If diagnostics fail:
  - environment or resource issue
- If `irecovery -q` fails:
  - DFU/device/USB issue
- If `--validate-firmware` fails:
  - manifest/planning issue
- If dry-run works but live run fails immediately:
  - missing external component or wrapper/runtime issue
- If SHSH fails:
  - `tsschecker` issue
- If staging fails:
  - manifest/component resolution or external patching tool issue
- If send fails:
  - exploit/device-state/boot chain issue

## Minimal Useful Validation Without Full End-to-End Success

You can still get meaningful validation if only these succeed:

- `python odts.py --device-state`
- `python odts.py --diagnostic --json`
- `python odts.py --validate-firmware ...`
- `./resources/bin/irecovery -q`
- `python odts.py ... --dry-run`

That is enough to separate:

- host setup problems
- repo/resource problems
- manifest/planning problems
- DFU detection problems
- live execution problems
