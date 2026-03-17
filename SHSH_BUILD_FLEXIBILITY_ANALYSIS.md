# SHSH Build Flexibility Analysis

## Scope

This document captures what the current code and new host-only checks can say about SHSH build flexibility.

It does not assume the hypothesis is correct.

It does not authorize live execution.

## Current Question

Does the current code/toolchain truly require a build-matched SHSH blob, or can a currently signed blob for the same connected device context drive the host-side artifact generation path?

## What The New Safe Mode Tests

The new safe command:

```bash
./venv/bin/python odts.py --acquire-shsh --latest-signed
```

does two host-only things:

1. acquires SHSH for the currently signed build for the connected device context
2. runs a compatibility probe against the existing repo-aligned `19P647` artifact path

The compatibility probe checks:

- whether `img4tool` can derive `IM4M` from the acquired blob
- whether `img4tool` can wrap currently planned artifacts from the existing local payload set
- which artifacts succeed
- which artifacts are rejected before hardware is involved

## What The Current Code Appears To Require

From static tracing alone, the implementation still appears to want build-matched SHSH:

- planner, payloads, and SHSH are all normally aligned to one build
- later artifacts are explicitly signed with SHSH-backed metadata
- AMFI kernel flow still depends on SHSH-derived `IM4M`

So the implementation bias is:

- build-matched SHSH

## What The New Host-Only Probe Can Prove

If the host-only probe succeeds with a currently signed blob for the same device/board:

- the host-side `img4tool` path does not strictly require build-matched SHSH for the attempted artifact generation steps

If the host-only probe fails:

- the host-side toolchain itself rejects the mismatch before any hardware involvement

## What Still Remains Unknown Until Live Testing

Even if host-side wrapping succeeds, the following remain unknown:

- whether the device will accept the resulting artifacts in the real boot flow
- whether early patched stages truly relax all later signature/version enforcement needed by the current chain
- whether some artifacts are host-side wrappable but still device-side invalid
- whether send ordering or later-stage firmware semantics break on build mismatch

So host-only success would mean:

- promising compatibility signal

not:

- proven boot compatibility

## Current Conclusion

The current codebase still expresses a build-matched design.

The new `--latest-signed` mode is therefore a hypothesis probe, not a final answer:

- if host-side wrapping works, build-matched SHSH may be an implementation dependency rather than a strict host-side requirement
- if host-side wrapping fails, build-matched SHSH remains a hard host-side dependency for the current toolchain path

Either way, live behavior remains unknown until separate controlled validation.
