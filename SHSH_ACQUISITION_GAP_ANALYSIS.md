# SHSH Acquisition Gap Analysis

## Current Invocation Before The Fix

The new safe SHSH flow originally invoked:

```bash
tsschecker -d iBridge2,14 -e <ECID> -i 6.1 -s
```

Characteristics:

- device model supplied
- ECID supplied
- version supplied
- no explicit board config
- no explicit build ID
- no explicit BuildManifest
- no explicit install type flag

## Legacy Invocation

Legacy ODTS in [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py) invoked the wrapped equivalent of:

```bash
tsschecker -d <deviceModel> -e <ECID> -i <iOSVersion> -s
```

Observed legacy behavior:

- no explicit `-B` boardconfig
- no explicit `-Z` buildid
- no explicit `-m` BuildManifest
- no explicit `-u` update-install flag
- no bridgeOS-specific `tsschecker` branch in ODTS itself

## Exact Mismatch

The mismatch was not between old ODTS arguments and new ODTS arguments.

The mismatch was between:

- what legacy ODTS happened to pass
- and what the current modernized code now knows about the selected target

The modernized safe flow already had:

- connected board config `j152fap`
- repo-aligned build `19P647`
- repo-aligned `BuildManifest.plist`

but the first `--acquire-shsh` version did not pass that context through to `tsschecker`.

## Likely Reason BuildIdentity Selection Failed

Observed failure:

- firmware URL resolved correctly
- BuildManifest opened correctly
- `tsschecker` failed selecting a BuildIdentity for `installType=Erase`
- fallback to `installType=Update` also failed

Most likely reason:

- `tsschecker` could not disambiguate the correct bridgeOS/T2 BuildIdentity from device model + version alone

For `iBridge2,14` / `19P647`, the manifest contains multiple identities and selection is board-specific.

The planner already resolves the correct identity as:

- product: `iBridge2,14`
- board config: `j152fap`
- build: `19P647`
- erase variant: `Customer Erase Install (IPSW)`

So the missing context was:

- `-B j152fap`
- `-Z 19P647`
- `-m resources/ipwndfu8012/BuildManifest.plist`

## Updated Invocation

The safe SHSH acquisition wrapper now uses the richer invocation when available:

```bash
tsschecker -d iBridge2,14 -e <ECID> -Z 19P647 -B j152fap -m resources/ipwndfu8012/BuildManifest.plist -s
```

Notes:

- `-Z` is preferred over `-i` when the exact build is known
- `-B` supplies the board identity already selected by planning/device detection
- `-m` supplies the repo-aligned manifest explicitly when available
- `-u` is still not forced because the planner-selected identity is currently an erase/install flow

## Diagnostic Additions

`--acquire-shsh` now reports:

- full `tsschecker` command
- working directory
- selected device/build/version
- board config
- whether a BuildManifest was explicitly supplied
- manifest path
- temp files created during acquisition

## Current Conclusion

The original safe SHSH implementation failed because it was too generic for the bridgeOS/T2 identity-selection problem.

The minimal parity-oriented fix is not exploit-related.

It is simply:

- pass the board identity
- pass the exact build ID
- pass the explicit manifest when available

If SHSH acquisition still fails after this, the remaining issue is likely in:

- `tsschecker` bridgeOS BuildIdentity handling itself
- install-type expectations internal to `tsschecker`
- or additional T2-specific selection assumptions outside ODTS
