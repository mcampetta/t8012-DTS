# ODTS
## What is OSDT?

Script for mounting volumes on Checkm8 vulnerable iOS devices via Ramdisk based on PyBoot by Matty [(moski)](https://twitter.com/moski_dev)

## DISCLAIMER

MACOS ONLY - Don't ask for Windows support

## Current device support

- T8012 T2 devices. 

## Usage
```
E.G './odts.py -i iBridge2,5 6.1'

Ontrack Data Transfer Setup - A tool for signing and loading firmware images that allow us to ramdisk and mount the volume on T2 Mac devices. Written by Martin, @hotshotmc.

optional arguments:
  -h, --help          show this help message and exit
  -i, --ios   iOS version you wish to boot (DEVICE IOS)
  -q, --ipsw  Path to downloaded IPSW (PATH DEVICE)
  -b, --bootlogo  Path to .PNG you wish to use as a custom Boot Logo (LOGO)
  -p, --pwn           Enter PWNDFU mode, which will also apply signature patches
  --amfi              Apply AMFI patches to kernel (Beta)
  --debug             Send verbose boot log to serial for debugging
  -d, --dualboot  Name of system partition you wish to boot (e.g disk0s1s3 or disk0s1s6)
  -a, --bootargs      Custom boot-args, will prompt user to enter, don't enter a value upon running ODTS (Default is '-v')
  -v, --version       List the version of the tool
  -c, --credits       List credits
  -f, --fix           Fix img4tool/irecovery related issues

EXAMPLE USAGE: ./odts.py -i iBridge2,5 6.1  -a
```

## Instructions

1. cd into the ODTS directory
2. Run pip3 install -r requirements.txt
3. Connect your device in DFU mode to your computer
4. Run ODTS with your desiered options - E.G 'python3 odts.py -i iBridge2,5 6.1'
5. If all worked correctly device should mount as a volume once the Ramdisk is pushed to it, this can be accessed in diskutility in MacOS 
6. Enjoy! 

## Known Issues

After a fresh or new install of python the system root certificate is not generated by default. Tmhis may generate an error indicating that python is unable to find the system certificates. It is sometimes necessary to install the system root certificate by running a file called "Install Certificates.command" in your pythons root install directory ("/Applications/Python 3.x on Mac" ). This will generate a system certificate and get passed errors that may be stemming from not having a valid system root certificate. 

## Credits

[Me] HotshotMC - https://twitter.com/themsukid

[Matty] [(moski)](https://twitter.com/moski_dev)

[axi0mX](https://twitter.com/axi0mX) - [ipwndfu/checkm8](https://github.com/axi0mX/ipwndfu)

[Thimstar](https://twitter.com/tihmstar) - [img4tool](https://github.com/tihmstar/img4tool), [tsschecker](https://github.com/tihmstar/tsschecker), [iBoot64Patcher](https://github.com/tihmstar/iBoot64Patcher)

[Linus Henze](https://twitter.com/LinusHenze) - [Fugu](https://github.com/LinusHenze/Fugu)

[akayn](https://twitter.com/_akayn) - [A11 sigcheckremover support](https://github.com/akayn/ipwndfu)

realnp - [ibootim](https://github.com/realnp/ibootim)

[dayt0n](https://twitter.com/daytonhasty) - [kairos](https://github.com/dayt0n/kairos)

[Marco Grassi](https://twitter.com/marcograss) - [PartialZip](https://github.com/marcograss/partialzip)

[Merculous](https://twitter.com/Vyce_Merculous) - [ios-python-tools](https://github.com/Merculous/ios-python-tools) (iphonewiki.py for keys)

0x7ff - [Eclipsa](https://github.com/0x7ff/eclipsa)

libimobiledevice team - [irecovery](https://github.com/libimobiledevice/libirecovery)

[Ralph0045](https://twitter.com/Ralph0045) - [dtree_patcher](https://github.com/Ralph0045/dtree_patcher)/[Kernel64Patcher](https://github.com/Ralph0045/Kernel64Patcher)

[mcg29_](https://twitter.com/mcg29_) - amfi patching stuff

[dora2ios](https://twitter.com/dora2ios) - [iPwnder32 (A7 checkm8)](https://github.com/dora2-iOS/iPwnder32)
