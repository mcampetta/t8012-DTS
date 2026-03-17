# Current Signed Blob Analysis

## Scope

This document records the current hypothesis:

- a currently signed SHSH blob for the same connected device context may still be usable in the hybrid legacy T2 flow
- even if the payloads and manifest remain aligned to `19P647`

This is not yet a claim that the hypothesis is true.

It is a host-only validation target.

## What Would Need To Stay The Same

For the hypothesis to make sense, the following would still need to match the connected target:

- ECID
- device identity
  - `iBridge2,14`
- board context
  - `j152fap`

These are the identity elements the current SHSH acquisition flow and legacy notes treat as essential.

## What Might Be Allowed To Differ

The hypothesis specifically allows that the SHSH blob’s signed build/version might differ from the payload/manifests currently staged for analysis.

Example:

- payloads and manifest remain `19P647`
- SHSH blob is acquired for a currently signed bridgeOS build for the same device identity

This is only plausible because the current flow is hybrid:

- early patched stages may relax later version/signature enforcement
- some transmitted artifacts may only need structured wrapping or device-valid signing metadata, not strict build coherence

## What The Current Code Assumes Is Build-Matched

The current implementation still leans heavily toward build-matched behavior:

- payload sourcing is planned from a selected BuildManifest
- SHSH acquisition normally targets the same selected build
- many later artifacts are signed with `img4tool -s resources/shsh.shsh`
- the AMFI kernel path derives `IM4M` from SHSH and then reuses it

So the implementation assumption is still:

- one coherent build for payloads, manifest, and SHSH

## What The Current Code Does Not Prove

The current code does not prove that build coherence is strictly required by the real boot flow after early pwned-DFU / `nop_image4.py` patching.

That uncertainty is exactly why the current signed-blob hypothesis is worth host-only testing.

## Host-Only Validation Meaning

The new safe mode:

```bash
./venv/bin/python odts.py --acquire-shsh --latest-signed
```

tests only this narrower question:

- can a currently signed blob for the same connected device context drive the host-side `img4tool` path against the existing `19P647`-aligned artifact generation flow

It does not prove:

- that the device will boot successfully
- that hardware will accept every resulting artifact
- that all build-mismatch risks are removed

## Practical Interpretation

If host-side artifact generation succeeds with a currently signed blob for the same device/board context, that would show:

- the host-side toolchain does not strictly enforce build-matched SHSH for at least some or all current wrapping steps

If host-side artifact generation fails, that would show:

- the current host-side toolchain itself still rejects the mismatch before hardware is involved

Either result is useful, but neither is a substitute for later controlled live validation.
