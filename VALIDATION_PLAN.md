# Validation Plan

## Safe Validation Available Now

These flows are safe and non-destructive:

- `python odts.py --diagnostic --json`
- `python odts.py --device-state`
- `python odts.py --device-state --json`
- `python odts.py --device-state --verbose`
- `python odts.py setup`
- `python odts.py setup --fetch-missing --dry-run`
- `python odts.py --validate-firmware --manifest /path/to/BuildManifest.plist --board-config j132ap`
- `python odts.py -q /path/to/file.ipsw iBridge2,5 --validate-firmware --board-config j132ap`

## What Safe Validation Covers

- BuildManifest parsing
- board/config matching
- board-specific component lookup
- staged artifact planning
- external tool presence/version inspection
- missing resource reporting

## What Safe Validation Does Not Cover

- DFU exploitation correctness
- GID/KBAG decryption correctness
- live `irecovery` image transfer
- actual boot chain success
- ramdisk behavior after boot
- host-side mounting of volumes

## Mac Validation Sequence

1. Restore missing critical resources:
   - `resources/bin/tsschecker`
   - `resources/ipwndfu8012/checkm8.py`
2. Install Python runtime deps.
3. Run `python odts.py --device-state`.
4. Run diagnostics.
5. Run firmware validation on the intended IPSW/manifest.
6. Run dry-run operational flows.
7. Only then attempt live device interaction.

## Test Coverage

Current automated tests only cover safe logic:

- device parsing
- IPSW extraction helper behavior
- setup inspection
- external wrapper behavior
- firmware manifest parsing
- firmware artifact planning
- stage reporting
