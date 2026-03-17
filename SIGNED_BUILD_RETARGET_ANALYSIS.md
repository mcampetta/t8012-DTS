# Signed Build Retarget Analysis

## Scope

This document analyzes whether a future “latest signed build” mode is feasible.

It does not propose an incremental fix to the current 19P647-aligned pipeline.

It treats this as a redesign / compatibility project.

## Current State

Current lab findings:

- the legacy T2 implementation is hybrid by design
- it is still functionally SHSH-dependent overall
- the current payloads, manifests, and signing flow are aligned to build `19P647`
- SHSH for `19P647` is not currently available for `iBridge2,14`
- newer bridgeOS builds such as `23P3120` are signed

## Why A Newer Signed Blob Does Not Solve The Current Flow

An SHSH blob is not a generic signing token.

In the current pipeline it is tied to:

- the connected device
- the selected build
- the manifest-selected BuildIdentity and component set used for signing

The current flow expects:

- manifest-derived payload paths from the `19P647` BuildManifest
- patching and staging against `19P647` component artifacts
- IMG4 wrapping and signing decisions based on those same artifacts

So a blob for a newer signed build would not be valid for the current `19P647` flow because:

- the payload set would no longer match the signed build
- the BuildManifest identity would no longer match the signing request
- the signed artifact envelopes would be associated with different build content
- any assumptions baked into the execution chain about image layout, patch points, and load order could diverge

In short:

- `19P647` payloads plus `23P3120` SHSH is a mismatched pipeline

## What Would Have To Change To Retarget To A Signed Build

### 1. Payload Sourcing

The payload source would need to move from the current `19P647`-aligned artifacts to payloads extracted from the target signed build.

That means:

- new IPSW selection rules
- new payload extraction inputs
- new canonical local payload root contents

### 2. Manifest Selection

The planner would need to use the BuildManifest for the selected signed build, not the current repo-aligned `19P647` manifest.

That means:

- selecting a different BuildManifest
- resolving the correct `iBridge2,14` / `j152fap` BuildIdentity in that manifest
- ensuring all component paths and variants are replanned from that manifest

### 3. SHSH Acquisition

SHSH acquisition would need to target the same signed build chosen for payloads and manifest selection.

That means:

- build selection must become a first-class pipeline input
- SHSH acquisition must be locked to that build
- operator output must prove payload, manifest, and SHSH all target the same build

### 4. Signing Flow

The signing flow would need to wrap and sign artifacts produced from the new build’s payloads and manifest-derived identities.

That means:

- no reuse of `19P647`-aligned signed staging assumptions
- possible changes to which components are signed directly with SHSH versus `IM4M`
- revalidation of every `img4tool` invocation against the new build’s artifacts

### 5. Execution Compatibility Assumptions

This is the largest unknown.

Even if payload sourcing, manifest selection, and SHSH acquisition were aligned to a newer signed build, the legacy execution pipeline may still fail because it assumes:

- current patch points
- current image structure
- current KBAG / decrypt / patch / repackage expectations
- current send ordering
- current pwned-DFU / Image4-bypass behavior on the chosen build’s boot chain

So retargeting to a signed build is not just a sourcing problem.

It is also a compatibility validation project for:

- patchers
- signing steps
- boot chain sequencing
- exploit-adjacent assumptions

## Why This Is Not A Small Bugfix

This is not a narrow bugfix because the current repo is internally coherent around `19P647`.

Changing only one layer would create mismatches:

- new SHSH with old payloads
- new manifest with old patch assumptions
- new payloads with old signing flow expectations
- new build with unvalidated execution behavior

Any credible “latest signed build” mode would require coordinated redesign across:

- planning
- payload sourcing
- manifest resolution
- SHSH acquisition
- signing
- execution compatibility validation

## Recommended Classification

Treat “latest signed build” support as:

- redesign / compatibility project

Do not treat it as:

- minor wrapper fix
- small CLI enhancement
- isolated SHSH bug

## Practical Conclusion

Future support for a signed-build retarget mode may be feasible, but only if the pipeline is made build-coherent end to end.

That would require:

- selecting one signed build as the new source of truth
- replanning all payload and manifest inputs around that build
- reacquiring SHSH for that same build
- revalidating the legacy hybrid execution chain against that build

Until then, a newer signed blob is not a valid substitute for the current `19P647` payload/signing flow.
