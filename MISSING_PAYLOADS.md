# Missing Payloads

This file tracks the current unresolved firmware payload requirements for the connected `j152fap` target as reported by non-destructive preflight.

## Summary

Current blocker category:

- primary: `missing local files`
- secondary: `stale legacy assumptions`
- contract issue: `planning and legacy execution do not yet share one canonical extracted-firmware root`

Observed local state:

- `IPSW/` is absent in this checkout
- `resources/Firmware/` is absent in this checkout

Meaning:

- the current unresolved payloads are real missing-resolution blockers
- they are not caused by a false-positive probe against existing extracted payload trees

## `ibec`

- logical_name: `ibec`
- manifest_key: `iBEC`
- manifest-derived relative source_path: `Firmware/dfu/iBEC.j152f.RELEASE.im4p`
- expected source path(s):
  - `IPSW/Firmware/dfu/iBEC.j152f.RELEASE.im4p`
  - `resources/Firmware/Firmware/dfu/iBEC.j152f.RELEASE.im4p`
  - `Firmware/dfu/iBEC.j152f.RELEASE.im4p`
- how the path is derived:
  - BuildManifest `iBEC` path is treated as a path relative to the extracted IPSW root
- expected source type:
  - extracted IPSW tree
- consuming module:
  - `resources/img4.py`
- expectation state:
  - `legacy`
- blocker classification:
  - missing local files
  - stale legacy assumptions because one candidate path uses `resources/Firmware/Firmware/...`
- smallest non-destructive fix:
  - extract the selected IPSW into one canonical local root
  - normalize the planner/preflight contract to prefer that root first

## `ibss`

- logical_name: `ibss`
- manifest_key: `iBSS`
- manifest-derived relative source_path: `Firmware/dfu/iBSS.j152f.RELEASE.im4p`
- expected source path(s):
  - `IPSW/Firmware/dfu/iBSS.j152f.RELEASE.im4p`
  - `resources/Firmware/Firmware/dfu/iBSS.j152f.RELEASE.im4p`
  - `Firmware/dfu/iBSS.j152f.RELEASE.im4p`
- how the path is derived:
  - BuildManifest `iBSS` path is treated as a path relative to the extracted IPSW root
- expected source type:
  - extracted IPSW tree
- consuming module:
  - `resources/img4.py`
- expectation state:
  - `legacy`
- blocker classification:
  - missing local files
  - stale legacy assumptions because one candidate path uses `resources/Firmware/Firmware/...`
- smallest non-destructive fix:
  - same remediation as `ibec`

## `kernelcache`

- logical_name: `kernelcache`
- manifest_key: `KernelCache`
- manifest-derived relative source_path: `kernelcache.release.ibridge2p`
- expected source path(s):
  - `IPSW/kernelcache.release.ibridge2p`
  - `resources/Firmware/kernelcache.release.ibridge2p`
  - `kernelcache.release.ibridge2p`
- how the path is derived:
  - BuildManifest `KernelCache` path is already top-level in the IPSW rather than under `Firmware/`
- expected source type:
  - extracted IPSW tree
- consuming module:
  - `resources/img4.py`
- expectation state:
  - `legacy`
- blocker classification:
  - missing local files
  - path mismatch risk because kernelcache is treated as a top-level payload while other components are under `Firmware/...`
- smallest non-destructive fix:
  - keep kernelcache resolution in the canonical extracted IPSW root and document that top-level exception explicitly in planning/preflight

## `devicetree`

- logical_name: `devicetree`
- manifest_key: `DeviceTree`
- manifest-derived relative source_path: `Firmware/all_flash/DeviceTree.j152fap.im4p`
- expected source path(s):
  - `IPSW/Firmware/all_flash/DeviceTree.j152fap.im4p`
  - `resources/Firmware/Firmware/all_flash/DeviceTree.j152fap.im4p`
  - `Firmware/all_flash/DeviceTree.j152fap.im4p`
- how the path is derived:
  - BuildManifest `DeviceTree` path is treated as a path relative to the extracted IPSW root
- expected source type:
  - extracted IPSW tree
- consuming module:
  - `resources/img4.py`
- expectation state:
  - `legacy`
- blocker classification:
  - missing local files
  - stale legacy assumptions because one candidate path uses `resources/Firmware/Firmware/...`
- smallest non-destructive fix:
  - extract to canonical IPSW root and remove ambiguous duplicate firmware-root assumptions from planning and preflight

## `trustcache`

- logical_name: `trustcache`
- manifest_key: `StaticTrustCache`
- manifest-derived relative source_path: `Firmware/018-77781-055.dmg.trustcache`
- expected source path(s):
  - `IPSW/Firmware/018-77781-055.dmg.trustcache`
  - `resources/Firmware/Firmware/018-77781-055.dmg.trustcache`
  - `Firmware/018-77781-055.dmg.trustcache`
- how the path is derived:
  - BuildManifest `StaticTrustCache` path is treated as a path relative to the extracted IPSW root
- expected source type:
  - extracted IPSW tree
- consuming module:
  - `resources/img4.py`
- expectation state:
  - `legacy`
- blocker classification:
  - missing local files
  - stale legacy assumptions because one candidate path uses `resources/Firmware/Firmware/...`
- smallest non-destructive fix:
  - same canonical extracted-root remediation as above

## `aopfw`

- logical_name: `aopfw`
- manifest_key: `AOP`
- manifest-derived relative source_path: `Firmware/AOP/aopfw-t8012aop.im4p`
- expected source path(s):
  - `IPSW/Firmware/AOP/aopfw-t8012aop.im4p`
  - `resources/Firmware/Firmware/AOP/aopfw-t8012aop.im4p`
  - `Firmware/AOP/aopfw-t8012aop.im4p`
- how the path is derived:
  - BuildManifest `AOP` path is treated as a path relative to the extracted IPSW root
- expected source type:
  - extracted IPSW tree
- consuming module:
  - `resources/img4.py`
- expectation state:
  - `legacy`
- blocker classification:
  - missing local files
  - stale legacy assumptions because one candidate path uses `resources/Firmware/Firmware/...`
- smallest non-destructive fix:
  - same canonical extracted-root remediation as above

## `touch`

- logical_name: `touch`
- manifest_key: `Multitouch`
- manifest-derived relative source_path: `Firmware/J152f_Multitouch.im4p`
- expected source path(s):
  - `IPSW/Firmware/J152f_Multitouch.im4p`
  - `resources/Firmware/Firmware/J152f_Multitouch.im4p`
  - `Firmware/J152f_Multitouch.im4p`
- how the path is derived:
  - BuildManifest `Multitouch` path is treated as a path relative to the extracted IPSW root
- expected source type:
  - extracted IPSW tree
- consuming module:
  - `resources/img4.py`
- expectation state:
  - `legacy`
- blocker classification:
  - missing local files
  - stale legacy assumptions because one candidate path uses `resources/Firmware/Firmware/...`
- smallest non-destructive fix:
  - same canonical extracted-root remediation as above

## Proposed Remediation Plan

1. Define one canonical extracted-firmware root for non-destructive planning and legacy execution compatibility.
2. Resolve all payload lookups against that root first.
3. Keep fallback probing explicit and documented rather than implicit.
4. Treat the current `resources/Firmware/Firmware/...` candidates as legacy compatibility paths, not the preferred contract.
5. Rerun:
   - `./venv/bin/python odts.py --execution-graph`
   - `./venv/bin/python odts.py --preflight`
6. If a local IPSW archive is available, use the non-destructive helper:
   - `./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout`
   - `./venv/bin/python odts.py -q /path/to/restore.ipsw iBridge2,14 --payload-layout --extract-planned-payloads`
