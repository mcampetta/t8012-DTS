# Dependencies

## Python Runtime

- Python 3.10+ recommended
- Install with:

```bash
python -m pip install -r requirements.txt
```

## Python Packages

- `requests`
- `remotezip`
- `pyusb`
- `beautifulsoup4`

## Bundled Native Dependencies

The repo expects these prebundled files to remain present under `resources/bin/`:

- `img4tool`
- `img4`
- `irecovery`
- `tsschecker`
- `iBoot64Patcher`
- `Kernel64Patcher`
- `dtree_patcher`
- `ibootim`
- `iPwnder32`

These are legacy binaries, mostly macOS-targeted. They may be flagged by Windows security tooling because they are exploit or recovery utilities.

## Vendored Legacy Components

- `resources/ipwndfu/`
- `resources/ipwndfu8012/`

Notes:

- parts of these trees are still Python 2
- they were not fully ported during this pass
- they should be treated as legacy payloads until validated on macOS

## Network Dependencies

Operational flows may contact:

- `api.ipsw.me`
- IPSW CDN URLs returned by `ipsw.me`
- `theiphonewiki.com`

No runtime auto-install/download behavior remains in the first-party CLI.

An explicit bootstrap path now exists:

```bash
python odts.py setup --fetch-missing
```

It only populates supported repo-local resources and does not modify the host system outside the repository.


## Known Issues

- Windows cannot execute the bundled Mach-O tools
- some assets may trigger AV or Defender classifications as hacktools
- real device workflows still require manual macOS validation
