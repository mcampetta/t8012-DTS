# Signing Decoupling Analysis

## Scope

This document analyzes whether the current legacy T2 signing path can be decoupled from live Apple SHSH acquisition.

It does not change execution behavior.

It does not assume the bypass path fully replaces all signing requirements.

## Current `img4tool` Usage In This Pipeline

The current code uses `img4tool` in three distinct ways:

### 1. IM4P wrapping only

Used to create typed IM4P containers from raw payloads, for example:

- `ibec.patched`
- `ibss.patched`
- `kernel.im4p`
- `devicetree.im4p`
- `bootlogo.im4p`

These calls look like:

- `img4tool -c <out.im4p> -t <type> <payload>`

This is structural packaging, not SHSH-backed signing by itself.

### 2. SHSH-backed IMG4 creation with `-s`

Used heavily in [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py):

- `img4tool -c resources/StagedFiles/ibss.img4 -p resources/StagedFiles/ibss.patched -s resources/shsh.shsh`
- `img4tool -c resources/StagedFiles/ibec.img4 -p resources/StagedFiles/ibec.patched -s resources/shsh.shsh`
- `img4tool -c resources/StagedFiles/ramdisk.img4 -p resources/018-75901-013.dmg -t rdsk -s resources/shsh.shsh`
- `img4tool -c resources/StagedFiles/bootlogo.img4 ... -s resources/shsh.shsh`
- `signImages()` also signs:
  - `devicetree.img4`
  - `kernel.img4`
  - `trustcache.img4`
  - optional `aopfw.img4`
  - optional `isp.img4`
  - optional `callan.img4`
  - optional `touch.img4`

This is where the current implementation is functionally SHSH-dependent.

### 3. Deriving and reusing `IM4M`

The current code also runs:

- `img4tool -e -s resources/shsh.shsh -m resources/IM4M`

Then later:

- `img4tool -c resources/StagedFiles/kernel.img4 -p resources/StagedFiles/kernel.im4p -m ../IM4M`

So in the AMFI-patched kernel branch, SHSH is first converted into an `IM4M` payload, and that `IM4M` is then reused as signing metadata.

## What `resources/shsh.shsh` Contributes

From the current code and the upstream `img4tool` usage model, `resources/shsh.shsh` is not being used as a generic opaque file name.

It is the source of signing metadata that `img4tool` can:

- use directly with `-s`
- convert into `IM4M`
- verify against a `BuildManifest`

So the minimal useful property of `resources/shsh.shsh` in this pipeline is:

- it carries device/build-specific signing material that `img4tool` can embed or extract into Image4 metadata

## Can `IM4M` Be Reused From A Static Template

Not safely as a generic static template.

What appears feasible in principle:

- reuse an already derived `IM4M` or SHSH-backed signing artifact that matches the same device and build

What does not appear supported by the current design:

- one static `IM4M` reused across unrelated devices or builds

Reason:

- the current code and earlier SHSH analysis treat the signing material as device-specific and build-specific
- reusing a mismatched `IM4M` would just be another form of mismatched signing metadata

So:

- a previously derived matching `IM4M` might be reusable
- a generic static template is not supported by the current evidence

## Can `IM4M` Be Generated Locally

Not from the current first-party code alone.

Current evidence only shows local generation of `IM4M` from already valid SHSH material:

- `img4tool -e -s resources/shsh.shsh -m resources/IM4M`

That is not independent local generation.

It is extraction / conversion from previously acquired signing material.

So the current codebase does not demonstrate a path to generate the needed `IM4M` locally without first having valid SHSH-backed data.

## Can SHSH Be Bypassed Via `nop_image4.py`

Partially at most, based on the current evidence.

[resources/ipwndfu8012/nop_image4.py](/Users/kocrrd/Documents/t8012-DTS/resources/ipwndfu8012/nop_image4.py) patches out `image4_load` and prints:

- `Removed image_load call; all incoming images will be loaded as raw`

That strongly suggests the bypass can relax Image4 wrapper enforcement.

But the current execution pipeline does not rely on that as a full signing replacement.

Instead it still:

- sends `ibss.pwn` as a raw/patched artifact
- sends many later components as SHSH-backed `.img4` files

So the safest interpretation is:

- `nop_image4.py` likely explains why at least part of the chain can use raw/patched input
- it does not prove that every later SHSH-backed artifact could be replaced with unsigned or locally fabricated metadata in the current implementation

## Which Components Truly Look SHSH-Dependent In Current Code

Most clearly SHSH-dependent in the current implementation:

- `ibec.img4`
- `ramdisk.img4`
- `bootlogo.img4`
- `devicetree.img4`
- `kernel.img4`
- `trustcache.img4`
- optional `aopfw.img4`
- optional `isp.img4`
- optional `callan.img4`
- optional `touch.img4`

Partially decoupled already:

- `ibss`
  - transmitted as `ibss.pwn`
  - but the code still also constructs `ibss.img4`

AMFI-patched kernel branch:

- still depends on SHSH-derived `IM4M`

## Minimal Requirements For `img4tool` In This Pipeline

The current pipeline appears to need two different `img4tool` capabilities:

### Structural wrapping

- create IM4P containers from raw payloads
- change payload type tags
- extract / inspect payload metadata

This part may not fundamentally require live Apple signing material.

### Signing metadata injection

- create final IMG4 containers with SHSH-backed `-s`
- or with SHSH-derived `-m IM4M`

This is the part that remains coupled to valid signing material in the current implementation.

## Can SHSH Dependency Be Removed Without Breaking The Current Flow

Not on current evidence.

The codebase does not currently demonstrate that:

- all later boot artifacts can be sent raw after `nop_image4.py`
- a generic static `IM4M` is acceptable
- a locally fabricated `IM4M` is acceptable
- the SHSH-backed portions of the chain are merely accidental and safely removable

So the present answer is:

- no clear evidence that SHSH dependency can be removed without redesign and live compatibility validation

## Safest Non-Destructive Way To Test This Later

The safest future non-destructive validation path would be staged and host-focused:

1. compare artifact generation commands only
   - enumerate which outputs use `-s`
   - enumerate which outputs use `-m`
   - enumerate which outputs are only structurally wrapped
2. attempt host-only artifact generation experiments in isolation
   - never send to hardware
   - compare whether some components can still be packaged without SHSH-backed metadata
3. treat `ibss` separately from the rest of the chain
   - because current code already sends `ibss.pwn`
4. treat `kernel`, `devicetree`, `trustcache`, and `ibec` as higher-risk signing dependencies
   - because current code explicitly packages and transmits them as signed IMG4 artifacts

Any future attempt to remove SHSH from the chain should begin as:

- artifact-generation experiment only

not:

- live boot experiment

## Current Conclusion

The current legacy T2 pipeline appears to require:

- structural Image4 packaging for many artifacts
- SHSH-backed signing metadata for most final transmitted IMG4 artifacts
- exploit / Image4-bypass behavior for at least part of the early boot chain

So SHSH dependency cannot currently be considered removable based on architecture tracing alone.

At most, the analysis supports a narrower future question:

- whether some subset of later SHSH-backed artifacts are only conservatively signed today and could be retargeted to a different metadata strategy

That remains a redesign and validation project, not a current conclusion.
