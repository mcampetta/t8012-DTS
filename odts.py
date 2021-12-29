#!/usr/bin/env python3

import subprocess
from subprocess import check_output
import sys

#print("Recommended disabling gatekeeper in order to prevent further issues with binaries in this package\n\nPress enter to continue")
#input()
#cmd = 'sudo spctl --master-disable'
#subprocess.run(cmd, shell=True, check=True)

try:

    import argparse
    import requests
    import os
    import platform
    import plistlib
    import stat
    import re
    import shutil
    import time
    from zipfile import ZipFile
    from argparse import RawTextHelpFormatter
    from resources import img4, pwn, ipsw
    from resources.iospythontools import iphonewiki
    from resources.iospythontools import ipswapi
    from resources.iospythontools import utils

except:
    print("Detected first time setup. Installing dependencies")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    try:
        import argparse
        import requests
        import os
        import platform
        import plistlib
        import stat
        import re
        import shutil
        import time
        from zipfile import ZipFile
        from argparse import RawTextHelpFormatter
        from resources import img4, pwn, ipsw
        from resources.iospythontools import iphonewiki
        from resources.iospythontools import ipswapi
        from resources.iospythontools import utils
        print("Recommended disabling gatekeeper in order to prevent further issues with binaries in this package\n\nPress enter to continue")
        input()
        cmd = 'sudo spctl --master-disable'
        subprocess.run(cmd, shell=True, check=True)

    except:
        print("\n\nFailed to install dependencies, please manually run 'pip3 install -r requirements.txt' then re-run ODTS") # Simplest way to make sure the user knows what to do if they haven't installed dependencies yet
        #exit(0)
    print("\n\nSuccessfully installed dependencies!\n\nContinuing with ODTS...\n")


tool_version = '\033[92m' + "Beta 0.0.1" + '\033[0m'

def removeFiles():
    removeFiles = [
        'resources/StagedFiles/devicetree.im4p',
        'resources/StagedFiles/devicetree.img4',
        'resources/StagedFiles/ibec.im4p',
        'resources/StagedFiles/ibec.img4',
        'resources/StagedFiles/ibec.raw',
        'resources/StagedFiles/ibec.pwn',
        'resources/StagedFiles/ibec.patched',
        'resources/StagedFiles/ibss.im4p',
        'resources/StagedFiles/ibss.img4',
        'resources/StagedFiles/isp.im4p',
        'resources/StagedFiles/isp.img4',
        'resources/StagedFiles/ibss.raw',
        'resources/StagedFiles/ibss.pwn',
        'resources/StagedFiles/ibss.patched',
        'resources/StagedFiles/kernel.im4p',
        'resources/StagedFiles/kernel.img4',
        'resources/StagedFiles/kernel.raw',
        'resources/StagedFiles/kernel.patched',
        'resources/StagedFiles/kernel.compressed',
        'resources/StagedFiles/manifest.plist',
        'resources/StagedFiles/shsh.shsh',
        'resources/StagedFiles/IM4M',
        'resources/StagedFiles/devicetree.raw',
        'resources/StagedFiles/devicetree.patched',
        'resources/StagedFiles/trustcache.im4p',
        'resources/StagedFiles/trustcache.img4',
        'resources/StagedFiles/bootlogo.im4p',
        'resources/StagedFiles/bootlogo.ibootim',
        'resources/StagedFiles/bootlogo.img4',
        'resources/StagedFiles/aopfw.img4',
        'resources/StagedFiles/aopfw.im4p',
        'resources/StagedFiles/touch.im4p',
        'resources/StagedFiles/touch.img4',
        'resources/StagedFiles/callan.im4p',
        'resources/StagedFiles/callan.img4',
    ]

    for item in removeFiles: # removes files from above list
        if os.path.isfile(item):
            os.remove(item)
    return

def main():
    
    removeFiles()
    #clean() # removes potentially out of date JSON files 

    text = 'Ontrack Data Transfer Setup - A tool for signing and loading firmware images that allow us to ramdisk and mount the volume on T2 Mac devices. Written by Martin, @hotshotmc.'
    parser = argparse.ArgumentParser(description=text, formatter_class=RawTextHelpFormatter, usage=f"./odts.py -i 'DEVICE IOS'\n\nE.G './odts.py -i iBridge2,5 6.1'\n\nCurrent ODTS version is: {tool_version}", epilog="EXAMPLE USAGE: ./odts.py -i iBridge2,5 6.1  -a")
    parser.add_argument("-i", "--ios", help="iOS version you wish to boot (DEVICE IOS)", nargs=2, metavar=('\b', '\b'))
    parser.add_argument("-q", "--ipsw", help="Path to downloaded IPSW (PATH DEVICE)", nargs=2, metavar=('\b', '\b'))
    parser.add_argument("-b", "--bootlogo", help="Path to .PNG you wish to use as a custom Boot Logo (LOGO)", nargs=1, metavar=("\b"))
    parser.add_argument('-p', '--pwn', help='Enter PWNDFU mode, which will also apply signature patches', action='store_true')
    parser.add_argument("--amfi", help="Apply AMFI patches to kernel (Beta)", action="store_true")
    parser.add_argument("--debug", help="Send verbose boot log to serial for debugging", action="store_true")
    parser.add_argument("-d", "--dualboot", help="Name of system partition you wish to boot (e.g disk0s1s3 or disk0s1s6)", nargs=1, metavar=("\b"))
    parser.add_argument("-a", "--bootargs", help="Custom boot-args, will prompt user to enter, don't enter a value upon running ODTS (Default is '-v')", action='store_true')
    parser.add_argument("-v", "--version", help="List the version of the tool", action="store_true")
    parser.add_argument("-c", "--credits", help="List credits", action="store_true")
    parser.add_argument("-f", "--fix", help="Fix img4tool/irecovery related issues", action="store_true")


    if platform.system() == 'Darwin':  # If not MacOS then exit basically
        pass
    elif platform.system() == "Linux":
        sys.exit('\033[91m' + "\nSorry this OS is not currently supported!\n\nOnly MacOS machines (Hackintosh or a legitimate Apple computer) are support as of now.\n" + '\033[0m')
    elif platform.system() == "Windows":
        sys.exit('\033[91m' + "\nSorry Windows will never be supported!\n\nOnly MacOS machines (Hackintosh or a legitimate Apple computer) are support as of now.\n" + '\033[0m')
    else:
        sys.exit("Wtf are you even running this on?")

    args = parser.parse_args()
    if args.fix:

        # We need to prompt for what the user needs to fix

        response = input("What do you need to fix?\n1. img4tool\n2. irecovery\n3. Both\n(1/2/3)\n")
        if response == "1":
            print("Downloading latest img4tool release from Tihmstar's github...")
            
            if os.path.exists("img4tool.zip"):
                os.remove("img4tool.zip")

            url = "https://github.com/tihmstar/img4tool/releases/download/182/buildroot_macos-latest.zip"
            r = requests.get(url, allow_redirects=True)

            open('img4tool.zip', 'wb').write(r.content)

            if os.path.exists("img4tool"):
                shutil.rmtree("img4tool")
                os.mkdir("img4tool")
            else:
                os.mkdir("img4tool")
            
            shutil.move("img4tool.zip", "img4tool/img4tool.zip")
            os.chdir("img4tool")

            with ZipFile('img4tool.zip', 'r') as zipObj:
                
                zipObj.extractall()
            
            os.chdir("../")
            os.remove("./resources/bin/img4tool")
            shutil.move("img4tool/buildroot_macos-latest/usr/local/bin/img4tool", "resources/bin/img4tool")

            st = os.stat('resources/bin/img4tool')
            os.chmod('resources/bin/img4tool', st.st_mode | stat.S_IEXEC)

            if os.path.exists("/usr/local/include/img4tool"):
                shutil.rmtree("/usr/local/include/img4tool")

            shutil.move("img4tool/buildroot_macos-latest/usr/local/include/img4tool", "/usr/local/include/img4tool")

            if os.path.exists("/usr/local/lib/libimg4tool.a"):
                os.remove("/usr/local/lib/libimg4tool.a")
            
            shutil.move("img4tool/buildroot_macos-latest/usr/local/lib/libimg4tool.a", "/usr/local/lib/libimg4tool.a")

            if os.path.exists("/usr/local/lib/libimg4tool.la"):
                os.remove("/usr/local/lib/libimg4tool.la")
            
            shutil.move("img4tool/buildroot_macos-latest/usr/local/lib/libimg4tool.la", "/usr/local/lib/libimg4tool.la")

            if os.path.exists("/usr/local/lib/pkgconfig/libimg4tool.pc"):
                os.remove("/usr/local/lib/pkgconfig/libimg4tool.pc")
            
            shutil.move("img4tool/buildroot_macos-latest/usr/local/lib/pkgconfig/libimg4tool.pc", "/usr/local/lib/pkgconfig/libimg4tool.pc")

            print("img4tool has been installed, you can now use ODTS normally!")
        elif response == "2":

            if os.path.exists("/usr/local/bin/brew"):
                print("Found brew, installing libirecovery now")
            else:
                print("Error: Could not find brew!")
                choice = input("Do you want to install brew now to install irecovery? (y/n)")
                if choice == "y" or choice == "Y":
                    cmd = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"'
                    so = subprocess.Popen(cmd, shell=True)
                    print(so)
                else:
                    print("You will need to manually install brew from brew.sh to install irecovery. Exiting...")
                    exit(0)
            cmd = 'brew install --HEAD libimobiledevice'
            subprocess.run(cmd, shell=True, check=True)

            cmd = 'brew link --overwrite libimobiledevice'
            subprocess.run(cmd, shell=True, check=True)

            print("Downloading latest irecovery source from libimobiledevice's github...")

            url = "https://github.com/libimobiledevice/libirecovery/archive/master.zip"
            r = requests.get(url, allow_redirects=True)

            open('irecovery.zip', 'wb').write(r.content)

            if os.path.exists("irecovery"):
                shutil.rmtree("irecovery")
                os.mkdir("irecovery")
            else:
                os.mkdir("irecovery")
        
            shutil.move("irecovery.zip", "irecovery/irecovery.zip")
            os.chdir("irecovery")

            with ZipFile('irecovery.zip', 'r') as zipObj:
                
                zipObj.extractall()
            
            os.chdir("libirecovery-master")

            st = os.stat('autogen.sh')
            os.chmod('autogen.sh', st.st_mode | stat.S_IEXEC)

            subprocess.run("./autogen.sh", shell=True, check=True)

            subprocess.run("make", shell=True, check=True)

            subprocess.run("sudo make install", shell=True, check=True)

            if os.path.exists("/usr/local/bin/irecovery"):
                os.remove("../../resources/bin/irecovery")
                shutil.copy("/usr/local/bin/irecovery", "../../resources/bin/irecovery")
                st = os.stat('../../resources/bin/irecovery')
                os.chmod('../../resources/bin/irecovery', st.st_mode | stat.S_IEXEC)
            else:
                print("Something went wrong while compiling irecovery, please open an issue on Github with a screenshot of the above output. Exiting...")
                exit(0)

            print("irecovery has been installed, you can now use ODTS normally!")

        elif response == "3":
            print("Downloading latest img4tool release from Tihmstar's github...")
            
            if os.path.exists("img4tool.zip"):
                os.remove("img4tool.zip")

            url = "https://github.com/tihmstar/img4tool/releases/download/182/buildroot_macos-latest.zip"
            r = requests.get(url, allow_redirects=True)

            open('img4tool.zip', 'wb').write(r.content)

            if os.path.exists("img4tool"):
                shutil.rmtree("img4tool")
                os.mkdir("img4tool")
            else:
                os.mkdir("img4tool")
            
            shutil.move("img4tool.zip", "img4tool/img4tool.zip")
            os.chdir("img4tool")

            with ZipFile('img4tool.zip', 'r') as zipObj:
                
                zipObj.extractall()
            
            os.chdir("../")
            os.remove("./resources/bin/img4tool")
            shutil.move("img4tool/buildroot_macos-latest/usr/local/bin/img4tool", "resources/bin/img4tool")

            st = os.stat('resources/bin/img4tool')
            os.chmod('resources/bin/img4tool', st.st_mode | stat.S_IEXEC)

            if os.path.exists("/usr/local/include/img4tool"):
                shutil.rmtree("/usr/local/include/img4tool")

            shutil.move("img4tool/buildroot_macos-latest/usr/local/include/img4tool", "/usr/local/include/img4tool")

            if os.path.exists("/usr/local/lib/libimg4tool.a"):
                os.remove("/usr/local/lib/libimg4tool.a")
            
            shutil.move("img4tool/buildroot_macos-latest/usr/local/lib/libimg4tool.a", "/usr/local/lib/libimg4tool.a")

            if os.path.exists("/usr/local/lib/libimg4tool.la"):
                os.remove("/usr/local/lib/libimg4tool.la")
            
            shutil.move("img4tool/buildroot_macos-latest/usr/local/lib/libimg4tool.la", "/usr/local/lib/libimg4tool.la")

            if os.path.exists("/usr/local/lib/pkgconfig/libimg4tool.pc"):
                os.remove("/usr/local/lib/pkgconfig/libimg4tool.pc")
            
            shutil.move("img4tool/buildroot_macos-latest/usr/local/lib/pkgconfig/libimg4tool.pc", "/usr/local/lib/pkgconfig/libimg4tool.pc")
            
            
            if os.path.exists("/usr/local/bin/brew"):
                print("Found brew, installing libirecovery now")
            else:
                print("Error: Could not find brew!")
                choice = input("Do you want to install brew now to install irecovery? (y/n)")
                if choice == "y" or choice == "Y":
                    cmd = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"'
                    so = subprocess.Popen(cmd, shell=True)
                    print(so)
                else:
                    print("You will need to manually install brew from brew.sh to install irecovery. Exiting...")
                    exit(0)
            cmd = 'brew install --HEAD libimobiledevice'
            subprocess.run(cmd, shell=True, check=True)

            cmd = 'brew link --overwrite libimobiledevice'
            subprocess.run(cmd, shell=True, check=True)

            print("Downloading latest irecovery source from libimobiledevice's github...")

            url = "https://github.com/libimobiledevice/libirecovery/archive/master.zip"
            r = requests.get(url, allow_redirects=True)

            open('irecovery.zip', 'wb').write(r.content)

            if os.path.exists("irecovery"):
                shutil.rmtree("irecovery")
                os.mkdir("irecovery")
            else:
                os.mkdir("irecovery")
        
            shutil.move("irecovery.zip", "irecovery/irecovery.zip")
            os.chdir("irecovery")

            with ZipFile('irecovery.zip', 'r') as zipObj:
                
                zipObj.extractall()
            
            os.chdir("libirecovery-master")

            st = os.stat('autogen.sh')
            os.chmod('autogen.sh', st.st_mode | stat.S_IEXEC)

            subprocess.run("./autogen.sh", shell=True, check=True)

            subprocess.run("make", shell=True, check=True)
            
            subprocess.run("sudo make install", shell=True, check=True)

            if os.path.exists("/usr/local/bin/irecovery"):
                os.remove("../../resources/bin/irecovery")
                shutil.copy("/usr/local/bin/irecovery", "../../resources/bin/irecovery")
                st = os.stat('../../resources/bin/irecovery')
                os.chmod('../../resources/bin/irecovery', st.st_mode | stat.S_IEXEC)
            else:
                print("Something went wrong while compiling irecovery, please open an issue on Github with a screenshot of the above output. Exiting...")
                exit(0)

            print("irecovery has been installed, you can now use ODTS normally!")
        else:
            print("Unrecognized input, exiting...")
            exit(0)
        exit(0)
    if args.credits:
        print('\033[95m' + "\nODTS Createdd by: Martin - @hotshotmc\n" + '\033[0m')
        print('\033[95m' + "\nPyBoot Created by: Matty - @mosk_i\n" + '\033[0m')
        print('\033[94m' + "Other Tools by -\n" + '\033[0m')
        print("axi0mX - [ipwndfu/checkm8]")
        print("dayt0n - [kairos]")
        print("xerub - [img4]")
        print("Marco Grassi - [PartialZip]")
        print("Merculous - [ios-python-tools]")
        print("0x7ff - [Eclipsa]")
        print("Ralph0045 - [dtree_patcher/Kernel64Patcher]")
        print("mcg29_ - [amfi patching stuff]")
        print("libimobiledevice team - [irecovery]\n" + '\033[0m')
        sys.exit()
    elif args.pwn:
        pwn.pwndfumode()
        exit(22)
        
    elif args.ipsw:
        if args.amfi:
            amfiPatches = True
            input("Warning: To applying AMFI patches, you need to compile and install https://github.com/Ralph0045/liboffsetfinder64 otherwise it will not work.\nPress enter when you have done this or if you already have it installed.")
        else:
            amfiPatches = False
        if args.bootlogo:
            useCustomLogo = True
            logopath = args.bootlogo[0]
        else:
            useCustomLogo = False
            logopath = "null"
        if args.dualboot:
            bootOtherOS = True
            sysPartName = args.dualboot[0]
            if args.debug:
                print("Debugging mode enabled! You can use a serial cable to see more output for debugging issues")
                bootArgs = f"-v serial=3 rd={sysPartName}"
            else:
                bootArgs = f"-v rd={sysPartName}"
            if args.bootargs:
                print(f"\n" + '\033[93m' + "WARNING:" + '\033[0m' + f"'-a' was specified indicating the user wanted to set custom boot-args, but '-d' was also set which currently doesn't support custom boot-args...\nIgnoring '-a' and continuing with '{bootArgs}' as the set boot-args.\n")
        else:
            bootOtherOS = False
            if args.bootargs:
                bootArgs = input("Please enter the boot-args you want to use then press enter: ")
            else:
                bootArgs = "rd=md0-v"
        
            
        print('\033[95m' + "Ontrack_T2Boot - A tool for tether booting Checkm8 vulnerable Mac devices by Martin, @mhotshotmc\n" + '\033[0m')
        print("Current version is: " + tool_version)
        print("User chose to use a locally stored IPSW, running some checks...")
        if os.path.exists("IPSW"):
            shutil.rmtree("IPSW")
        ipsw.unzipIPSW(args.ipsw[0])
        version = False
        supportedModels = str(ipsw.readmanifest("IPSW/BuildManifest.plist", version))
        if args.ipsw[1] in supportedModels:
            print("IPSW is for given device!")
        else:
            print("Sorry this IPSW is not valid for the given device, either run ODTS with -i to download the correct files or download the correct ipsw from ipsw.me")
            exit(0)
        version = True
        iosVersion = str(ipsw.readmanifest("IPSW/BuildManifest.plist", version))
        print(f"iOS version is: {iosVersion} and device model is: {args.ipsw[1]}")
        time.sleep(5)

        arewelocal = True
        img4.img4stuff(args.ipsw[1], iosVersion, useCustomLogo, logopath, arewelocal, bootOtherOS, bootArgs, amfiPatches)

        # now to pwn device
        print("Exploiting device with checkm8")
        try:
            pwn.pwndfumode()
        except:
            print("Looks like we couldn't PWN the T2 device. Power cycle it back into DFU mode and try again. If the problem persists check device connections.. Issues can be reported to me via teams or email also. Exiting for now..")
            exit(2)

        if args.ios[1] == "iPhone10,1" or args.ios[1] == "iPhone10,2" or args.ios[1] == "iPhone10,3" or args.ios[1] == "iPhone10,4" or args.ios[1] == "iPhone10,5" or args.ios[1] == "iPhone10,6" or args.ios[1] == "iBridge2,5":
            A10A11Check = True
        else:
            A10A11Check = False 

        # Send files to device and boot =)
        img4.sendImages(iosVersion, useCustomLogo, A10A11Check)

        print("Device should be booting!")
        exit(0)
    elif args.ios:
        print('\033[95m' + "Ontrack_T2Boot - A tool for tether booting Checkm8 vulnerable Mac devices by Martin, @mhotshotmc\n" + '\033[0m')
        print("Current version is: " + tool_version)
        if args.amfi:
            amfiPatches = True
            input("Warning: To applying AMFI patches, you need to compile and install https://github.com/Ralph0045/liboffsetfinder64 otherwise it will not work.\nPress enter when you have done this or if you already have it installed.")

        else:
            amfiPatches = False
        if args.bootlogo:
            useCustomLogo = True
            logopath = args.bootlogo[0]
        else:
            useCustomLogo = False
            logopath = "null"
        if args.dualboot:
            bootOtherOS = True
            sysPartName = args.dualboot[0]
            if args.debug:
                print("Debugging mode enabled! You can use a serial cable to see more output for debugging issues")
                bootArgs = f"-v serial=3 rd={sysPartName}"
            else:
                bootArgs = f"-v rd={sysPartName}"
            print(f"User choose to boot {args.ios[1]} from /dev/{sysPartName}.")
            if args.bootargs:
                print(f"\n" + '\033[93m' + "WARNING:" + '\033[0m' + f"'-a' was specified indicating the user wanted to set custom boot-args, but '-d' was also set which currently doesn't support custom boot-args...\nIgnoring '-a' and continuing with '{bootArgs}' as the set boot-args.\n")
        else:
            bootOtherOS = False
            if args.bootargs:
                bootArgs = input("Please enter the boot-args you want to use then press enter: ")
            else:
                bootArgs = "rd=md0 -v"

        print("Make sure your device is connected in DFU mode")
        #time.sleep(3)
        arewelocal = False
        #This section has been altered from ODTS significantly to account for the new use case.
        try:
            ecid = subprocess.check_output("irecovery -q | grep ECID:", shell=True)
            ecid = str(ecid[6 : 24].decode())
            bdid = subprocess.check_output("irecovery -q | grep BDID:", shell=True)
            bdid = str(bdid[6 : 24].decode())       
            shortbdid = bdid[2:4]
            shortbdid = shortbdid.upper() 
        except:
            print("Dirty state detected for T2 device. Please power cycle device and place back into DFU mode and try again.")
            exit(2)


        print(f"Retrieved ECID for device is: {ecid}\nRetrieved BDID for device is: {bdid}")     
        #ecid[ecid.find(start:='ECID:')+len(start):text.find(' CPFM:')]      
        #print(f"{ecid}")  
        #img4.img4stuff(args.ios[0], args.ios[1], useCustomLogo, logopath, arewelocal, bootOtherOS, bootArgs, amfiPatches)
        print(f"Looking up board configuration based on retrieved BDID of {bdid}")
        devicemaplinematch = subprocess.check_output(f"cat resources/device_map.txt | grep {shortbdid}", shell=True)
        devicemaplinematch = str(devicemaplinematch[40 : 60].decode())
        devicemaplinematch = devicemaplinematch.strip()
        print(f"Found match at {devicemaplinematch}") 
        shortdevicemaplinematch = devicemaplinematch.strip('ap')
        devicetype = str(args.ios[:1])
        stripped_devicetype = str(devicetype).replace('[','').replace(']','').replace('\'','').replace('\"','')
        deviceModel = stripped_devicetype
        devicetype = str(args.ios[1:])
        stripped_devicetype = str(devicetype).replace('[','').replace(']','').replace('\'','').replace('\"','')   
        iOSVersion = stripped_devicetype
        #print(deviceModel)
        #print(iOSVersion)
        #This section is for signing certificate
        so = subprocess.Popen(f"./resources/bin/tsschecker -d {deviceModel} -e {ecid} -i {iOSVersion} -s", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()
        dir_name = os.getcwd()
        test = os.listdir(dir_name)
        for item in test:
            if item.endswith(".shsh2"):
                shutil.move(os.path.join(dir_name, item), "./resources/shsh.shsh")
        shsh = "./resources/shsh.shsh"
        if os.path.exists(shsh):
            # Always good to check it saved properly
            print(f"Signing ticket for {deviceModel} with {ecid} on iOS {iOSVersion} saved successfully at {shsh}.. Moving on...")
            pass
        else:
            sys.exit("ERROR: Failed to save shsh")

        #This section pwns the T2 device and extracts the GID keys to decrypt the LLBs
        # now to pwn device
        print("PWNing T2 device to extract GID keys.. If this fails for more than a few seconds please restart the device and start over..")
        arewelocal = False
        img4.img4stuff(args.ios[0], args.ios[1], useCustomLogo, logopath, arewelocal, bootOtherOS, bootArgs, amfiPatches, devicemaplinematch)

        #This section decrypts and patches the LLBs

        #This section signs LLBs in preperation for a flash. 
        print("Signing firmware images before attempting to upload them to the device")

        so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/ibss.img4 -t ibss -p resources/Firmware/Firmware/dfu/iBSS.{shortdevicemaplinematch}.RELEASE.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()

        so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/ibec.img4 -t ibec -p resources/Firmware/Firmware/dfu/iBEC.{shortdevicemaplinematch}.RELEASE.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()

        print("IBSS and IBEC staged in StagedFiles dir")
        #exit(2)

        if args.ios[0] == "iPhone10,1" or args.ios[0] == "iPhone10,2" or args.ios[0] == "iPhone10,3" or args.ios[0] == "iPhone10,4" or args.ios[0] == "iPhone10,5" or args.ios[0] == "iPhone10,6" or args.ios[0] == "iPhone9,1" or args.ios[0] == "iPhone9,2" or args.ios[0] == "iPhone9,3" or args.ios[0] == "iPhone9,4" or args.ios[0] == "iBridge2,5":
            A10A11Check = True
            print("Your device has an A10/A11 CPU, you may run into some issues once booted. You have been warned...")
        if args.ios[0] == "iBridge2,5":
            T2Check = True
            print("Your device has a T2 chip and will have the latest version of iBridge flashed to it's LLBs")            
            time.sleep(1)
        else:
            A10A11Check = False 

        # Send files to device and boot =)
        img4.sendImages(devicetype, iOSVersion, A10A11Check)

        print("Device should be booting!")
        removeFiles()
        exit(2)

    elif args.version:
        sys.exit(f"Current version is: {tool_version}")

    else:
        sys.exit(parser.print_help(sys.stderr))


if __name__ == "__main__":
    main()
