# Hybrid Signing Flow Analysis

## Summary

The legacy T2 flow appears to be hybrid by design.

It does both:

- exploit / pwned-DFU / Image4-bypass setup
- SHSH-backed IMG4 signing for most of the boot chain

The current legacy implementation does not treat those as alternatives.

It uses both.

## Direct SHSH Consumers

`resources/shsh.shsh` is consumed by `img4tool` in two ways:

- directly as `img4tool -s resources/shsh.shsh`
- indirectly to derive `resources/IM4M`, which is then reused with `img4tool -m`

### Components Signed Directly With `-s resources/shsh.shsh`

From [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py):

- `ibss.img4`
- `ibec.img4`
- `ramdisk.img4`
- `bootlogo.img4`
- `devicetree.img4`
- `kernel.img4`
- `trustcache.img4`
- `aopfw.img4`
- `isp.img4`
- `callan.img4`
- `touch.img4`

## Components Not Signed With SHSH In The Same Way

### Raw / Patched iBSS Input

`iBSS` is first:

- extracted / decrypted / patched into `ibss.pwn`
- then sent as:
  - `StagedFiles/ibss.pwn`

That send path is not using `ibss.img4`.

So in the current send path:

- `ibss.pwn` is sent
- `ibss.img4` is still built, but not the artifact that is actually transmitted in `sendImages()`

This is the clearest evidence of the hybrid model.

### Kernel With AMFI Patch Path

When AMFI patching is enabled, the kernel path becomes:

1. derive `resources/IM4M` from `resources/shsh.shsh`
2. rebuild `kernel.im4p`
3. create `kernel.img4` using `-m ../IM4M`

So even this alternate path still depends on SHSH-backed signing material.

## Pwned-DFU / Image4-Bypass Path

The execution-side bypass path is:

1. [resources/pwn.py](/Users/kocrrd/Documents/t8012-DTS/resources/pwn.py)
   - `pwndfumode()` invokes `resources/ipwndfu8012/ipwndfu -p`
2. [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py)
   - `sendImages()` invokes `python2 ipwndfu8012/nop_image4.py`
3. [resources/ipwndfu8012/nop_image4.py](/Users/kocrrd/Documents/t8012-DTS/resources/ipwndfu8012/nop_image4.py)
   - patches out the `image4_load` call
   - prints:
     - `Removed image_load call; all incoming images will be loaded as raw`

The bundled README for `ipwndfu8012` states this explicitly:

- `nop_image4.py` allows booting extracted iBoot images without the img4 wrapper

## Which Stages Rely On The Bypass Path

The bypass path is used before image sending in [resources/img4.py](/Users/kocrrd/Documents/t8012-DTS/resources/img4.py):

- run `nop_image4.py`
- send `ibss.pwn`
- send `ibec.img4`
- send later boot artifacts over `irecovery`

So the pwned-DFU / Image4-bypass path is clearly part of the live execution chain.

## Which Stages Rely On SHSH-Backed Signing

The current implementation still constructs signed IMG4 artifacts for:

- `ibec`
- `ramdisk`
- `bootlogo`
- `devicetree`
- `kernel`
- `trustcache`
- optional `aopfw`
- optional `isp`
- optional `callan`
- optional `touch`

And it also constructs `ibss.img4`, even though the actual send path currently uses `ibss.pwn`.

## Does The Pipeline Appear Hybrid By Design

Yes.

The current legacy code strongly suggests a hybrid design:

- exploit / pwned DFU is used to get the device into a permissive state
- `nop_image4.py` relaxes or bypasses Image4 loading checks
- but the code still invests heavily in producing SHSH-backed signed IMG4 payloads

This is not a pure “unsigned raw images everywhere” pipeline.

It is also not a pure “normal signed restore-style boot” pipeline.

It is a mixed boot chain.

## Is SHSH Functionally Mandatory In The Current Legacy Implementation

Yes, in the current implementation.

Reasons:

- `resources/img4.py` always acquires SHSH before continuing
- many downstream artifacts are explicitly signed with `img4tool -s resources/shsh.shsh`
- the AMFI-patched kernel path still derives `IM4M` from SHSH
- preflight correctly flags missing `resources/shsh.shsh` as a signing-material blocker

## Is SHSH Strictly Required For Every Boot Component

No.

At least one important component, `ibss`, is transmitted in the current send path as a raw patched artifact:

- `StagedFiles/ibss.pwn`

That suggests the bypass path covers at least part of the chain.

But the current code still treats SHSH as mandatory overall because the rest of the chain is built around signed IMG4 artifacts.

## Architectural Conclusion

The current legacy T2 pipeline is:

- hybrid by design
- not purely dependent on signed IMG4 for every component
- but still functionally dependent on SHSH-backed signing material overall

So the correct present-day conclusion is:

- SHSH is not required for every single transmitted artifact
- SHSH is still functionally mandatory for the current legacy implementation as written
- any attempt to reduce or remove that dependency would be a behavior change, not a diagnostic clarification
