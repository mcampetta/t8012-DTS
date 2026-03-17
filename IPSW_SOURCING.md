# IPSW Sourcing

## Original Intended Firmware Sourcing Flow

The original tool supported two firmware sourcing modes.

### Remote mode

Triggered by:

- `-i DEVICE IOS`

Intended flow:

1. Query `ipsw.me` for the selected device and iOS version.
2. Resolve the matching build ID and Apple restore URL.
3. Use partial remote archive extraction to pull specific files directly from the restore IPSW.
4. Save `BuildManifest.plist` to `resources/manifest.plist`.
5. Save the selected firmware payloads directly into `resources/StagedFiles/`.

Implemented in:

- [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py)
- [resources/iospythontools/ipswapi.py](/Users/kocrrd/Documents/t8012-DTS/resources/iospythontools/ipswapi.py)
- [resources/iospythontools/manifest.py](/Users/kocrrd/Documents/t8012-DTS/resources/iospythontools/manifest.py)
- vendored duplicates under [iospythontools/](/Users/kocrrd/Documents/t8012-DTS/iospythontools)

Remote sources used:

- `https://api.ipsw.me/v4/device/{device}?type=ipsw`
- Apple restore URLs returned by the `ipsw.me` JSON

Code evidence:

- `APIParser.linksForDevice()` fetches the `ipsw.me` device JSON.
- `APIParser.downloadFileFromArchive()` opens the Apple restore URL with `RemoteZip` and extracts a single path.
- `img4stuff()` downloads:
  - `BuildManifest.plist`
  - `iBEC`
  - `iBSS`
  - `kernelcache`
  - `DeviceTree`
  - `trustcache`
  - `AOP`
  - `ISP`
  - `Callan`
  - `Multitouch`
  - `Stockholm`

### Local mode

Triggered by:

- `-q PATH DEVICE`

Intended flow:

1. Accept a full local IPSW archive from the operator.
2. Extract the IPSW into a repo-local `IPSW/` directory.
3. Move `IPSW/BuildManifest.plist` to `resources/manifest.plist`.
4. Move the needed payloads out of `IPSW/` into `resources/StagedFiles/`.

Implemented in:

- [resources/ipsw.py](/Users/kocrrd/Documents/t8012-DTS/resources/ipsw.py)
- [odts.py](/Users/kocrrd/Documents/t8012-DTS/odts.py)
- [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py)

Code evidence:

- `resources.ipsw.unzip_ipsw()` clears and recreates `IPSW/`, then `extractall()`s the archive there.
- `img4stuff(..., areWeLocal=True, ...)` expects:
  - `IPSW/BuildManifest.plist`
  - `IPSW/<kernelcache path>`
  - `IPSW/Firmware/...`

## Answers From The Actual Code

### Did the original tool automatically download an IPSW?

- Partially.
- In remote mode, it did **not** download the full IPSW by default.
- It queried `ipsw.me`, then extracted only specific files from the remote Apple restore archive using `RemoteZip`.
- It also contained a `downloadIPSW()` helper in `APIParser`, which could download the full IPSW via `urlretrieve`, but the main `img4stuff()` flow did not use that path.

### If so, from where and using what logic?

- Metadata source: `ipsw.me` device API
- Payload source: Apple restore URL embedded in the `ipsw.me` JSON
- Logic:
  - fetch JSON for the device
  - match `version -> buildid`
  - match `buildid -> url`
  - open that URL with `RemoteZip`
  - extract only the requested archive member

### Did it automatically extract the IPSW into the expected local layout?

- In local mode: yes, by extracting the full archive into `IPSW/`
- In remote mode: no, not into a full `IPSW/` tree
- Remote mode extracted selected files directly to working locations such as `resources/manifest.plist` and `resources/StagedFiles/*.im4p`

### What exact directory structure did the legacy execution path expect?

Local IPSW mode expected:

- `IPSW/BuildManifest.plist`
- `IPSW/Firmware/dfu/...`
- `IPSW/Firmware/all_flash/...`
- `IPSW/Firmware/AOP/...`
- `IPSW/Firmware/...`
- `IPSW/<top-level kernelcache file>`

Execution staging then moved files into:

- `resources/StagedFiles/ibec.im4p`
- `resources/StagedFiles/ibss.im4p`
- `resources/StagedFiles/kernel.im4p`
- `resources/StagedFiles/devicetree.im4p`
- `resources/StagedFiles/trustcache.im4p`
- `resources/StagedFiles/aopfw.im4p`
- `resources/StagedFiles/isp.im4p`
- `resources/StagedFiles/callan.im4p`
- `resources/StagedFiles/touch.im4p`
- `resources/StagedFiles/stockholm.im4p`

### Was the BuildManifest bundled while the rest of the payloads were expected to be downloaded separately?

- Yes, in the current repo there is a bundled manifest copy at:
  - [resources/manifest.plist](/Users/kocrrd/Documents/t8012-DTS/resources/manifest.plist)
  - [resources/ipwndfu8012/BuildManifest.plist](/Users/kocrrd/Documents/t8012-DTS/resources/ipwndfu8012/BuildManifest.plist)
- But the legacy operational flow still expected the real payload files to come from either:
  - remote archive extraction, or
  - a fully extracted local IPSW under `IPSW/`

So the bundled manifest was not sufficient by itself for live staging.

## Does The Original Logic Still Exist?

### Still present

- `ipsw.me` lookup logic
- Apple archive member extraction with `RemoteZip`
- full local IPSW extraction into `IPSW/`
- manifest-based payload name/path selection

### Still usable

- local IPSW extraction helper in [resources/ipsw.py](/Users/kocrrd/Documents/t8012-DTS/resources/ipsw.py)
- safe planning and payload-layout validation helpers in first-party code

### Broken or stale

- remote archive extraction is legacy and dependent on:
  - `remotezip`
  - `ipsw.me`
  - current Apple archive layout
- execution-side consumers still assume older repo-local path conventions in places
- planning and execution do not yet share one canonical payload-root contract

## What Operator Action Is Needed On This Lab Machine?

Current lab conclusion:

- the remaining hard preflight blocker is missing local payload material

Exact operator action:

1. Obtain a valid local restore IPSW for the connected `j152fap` target family.
2. Validate it non-destructively:

```bash
./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout
```

3. If the helper shows the required files are present in the archive, extract only the planned payloads into the canonical local layout:

```bash
./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout --extract-planned-payloads
```

4. Rerun:

```bash
./venv/bin/python odts.py --preflight
```

## Current Best Interpretation

- Yes, obtaining the correct IPSW is the only remaining **hard payload-material blocker** reported by preflight.
- No, that alone does not prove the repo is ready for controlled live-step testing.
- After payload extraction, the next gating question becomes whether the first execution-side step, `enter-pwned-dfu`, is sufficiently observable and acceptable to test.
