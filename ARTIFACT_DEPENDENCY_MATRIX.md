# Artifact Dependency Matrix

## Scope

This matrix distinguishes:

- what the current legacy implementation does
- what the boot flow may actually require

It does not claim that every current SHSH-backed artifact is truly enforced by hardware at that stage.

It only classifies what can be inferred from the present code and architecture tracing.

## Matrix

| Artifact | How It Is Currently Generated | Current Code Signs It With SHSH | Where It Is Transmitted | Early Boot Patching May Plausibly Relax Enforcement | Confidence |
| --- | --- | --- | --- | --- | --- |
| `ibss.pwn` | `img4tool -e` decrypts `ibss.im4p`, patcher produces `ibss.pwn`, `img4tool` also creates `ibss.patched` and `ibss.img4` but send path uses `ibss.pwn` | No for transmitted artifact | `sendImages()` sends `StagedFiles/ibss.pwn` via `irecovery -f` | Yes. This is the clearest bypass-backed artifact in the current chain because `nop_image4.py` runs first and the transmitted artifact is raw/patched, not signed IMG4 | High |
| `ibec.img4` | `img4tool -e` decrypts `ibec.im4p`, patcher produces `ibec.pwn`, `img4tool -c ... -t ibec` creates `ibec.patched`, then `img4tool -c ... -p ... -s resources/shsh.shsh` creates `ibec.img4` | Yes | `sendImages()` sends `StagedFiles/ibec.img4` | Plausible but not proven. Early patching may relax enforcement, but current code still wraps and signs it explicitly | Medium |
| `bootlogo.img4` | `ibootim` creates bootlogo payload, `img4tool -c ... -t logo` creates `bootlogo.im4p`, then `img4tool -c ... -p ... -s resources/shsh.shsh` creates `bootlogo.img4` | Yes | `sendImages()` sends `StagedFiles/bootlogo.img4` | Plausible but unclear. Cosmetic artifact may not need the same enforcement as core boot objects after early patching, but current code signs it | Low |
| `devicetree.img4` | `devicetree.im4p` is extracted or patched, then `signImages()` signs `devicetree.img4` with SHSH | Yes | `sendImages()` sends `StagedFiles/devicetree.img4` | Plausible but unknown. It is sent after early boot patching, but current implementation still treats it as signed IMG4 | Medium |
| `aopfw.img4` | `aopfw.im4p` extracted from IPSW, then `signImages()` signs `aopfw.img4` with SHSH | Yes | `sendImages()` sends `StagedFiles/aopfw.img4` on A10/A11/T2 path | Plausible but unknown. It is a later firmware payload, so relaxed enforcement is conceivable, but not demonstrated | Low |
| `isp.img4` | `isp.im4p` extracted, then `signImages()` signs `isp.img4` with SHSH | Yes | `sendImages()` sends `StagedFiles/isp.img4` on A10/A11/T2 path | Plausible but unknown. Same reasoning as `aopfw.img4` | Low |
| `callan.img4` | `callan.im4p` extracted, then `signImages()` signs `callan.img4` with SHSH | Yes | `sendImages()` sends `StagedFiles/callan.img4` on A10/A11/T2 path | Plausible but unknown. Later-stage firmware object, but no proof that SHSH is only legacy conservatism | Low |
| `touch.img4` | `touch.im4p` extracted, then `signImages()` signs `touch.img4` with SHSH | Yes | `sendImages()` sends `StagedFiles/touch.img4` on A10/A11/T2 path | Plausible but unknown. Same reasoning as `callan.img4` | Low |
| `trustcache.img4` | `trustcache.im4p` extracted, then `signImages()` signs `trustcache.img4` with SHSH | Yes | `sendImages()` sends `StagedFiles/trustcache.img4` for non-10.x/non-11.x flow | Plausible but unknown. It is sent later, but the trustcache role suggests it may still be semantically important even in a relaxed flow | Medium |
| `kernel.img4` | `kernel.im4p` extracted; normal path signs with SHSH in `signImages()`, AMFI path derives `IM4M` from SHSH then rebuilds `kernel.img4` with `-m ../IM4M` | Yes, either directly with `-s` or indirectly through SHSH-derived `IM4M` | `sendImages()` sends `StagedFiles/kernel.img4` | Plausible but unproven. Early patching may relax later enforcement, but current code still strongly treats kernel as SHSH-dependent | Medium |

## Interpretation

### Clearly Bypass-Backed

- `ibss.pwn`

Reason:

- `nop_image4.py` runs before transmission
- the actual transmitted artifact is raw/patched, not SHSH-backed IMG4

### Clearly SHSH-Backed In Current Implementation

- `ibec.img4`
- `bootlogo.img4`
- `devicetree.img4`
- `aopfw.img4`
- `isp.img4`
- `callan.img4`
- `touch.img4`
- `trustcache.img4`
- `kernel.img4`

Reason:

- the current code explicitly builds and transmits them as SHSH-backed or SHSH-derived IMG4 artifacts

### Unknown Whether SHSH Is Structurally Required Or Just Legacy Implementation Choice

- `ibec.img4`
- `bootlogo.img4`
- `devicetree.img4`
- `aopfw.img4`
- `isp.img4`
- `callan.img4`
- `touch.img4`
- `trustcache.img4`
- `kernel.img4`

Reason:

- they are SHSH-backed in the implementation
- but the existence of `nop_image4.py` and the raw `ibss.pwn` send path means the implementation may be more conservative than the actual boot-flow minimum
- current tracing alone cannot prove which of those later artifacts truly need valid SHSH-derived metadata at boot time

## Practical Conclusion

The current code proves:

- at least one early artifact is bypass-backed
- most later transmitted artifacts are SHSH-backed in the implementation

It does not prove:

- that every later SHSH-backed artifact is intrinsically required to remain SHSH-backed in the real boot flow

So the current state should be read as:

- implementation dependency: strong for most later artifacts
- true boot-flow dependency: only partially known from static tracing
