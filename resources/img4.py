import os
import re
import shutil
import subprocess
import sys
import time
from resources.ipwndfu import checkm8, dfu, usbexec 
from subprocess import check_output
from resources.pwn import pwndfumode, decryptKBAG, pwndfumodeKeys

import requests

from resources.iospythontools import iphonewiki, ipswapi, utils

def patchThing():
    #Copyright (c) 2020, @mcg29_

    # Code used with permission from @mcg29_
    # Original code from: https://github.com/dualbootfun/dualbootfun.github.io/blob/master/source/compareFiles.py

	patched = open("resources/StagedFiles/kernel.patched", "rb").read()
	original = open("resources/StagedFiles/kernel.raw", "rb").read()
	lenP = len(patched)
	lenO = len(original)
	if lenP != lenO:
		print("size does not match, can't compare files! exiting...")
		sys.exit(1)
	diff = []
	for i in range(lenO):
		originalByte = original[i]
		patchedByte = patched[i]
		if originalByte != patchedByte:
			diff.append([hex(i),hex(originalByte), hex(patchedByte)])	
	diffFile = open('resources/StagedFiles/kc.bpatch', 'w+')
	diffFile.write('#AMFI\n\n')
	for d in diff:
		data = str(d[0]) + " " + (str(d[1])) + " " + (str(d[2]))
		diffFile.write(data+ '\n')
		print(data)

def signImages(A10A11Check):
    print("Signing boot files")

    so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/devicetree.img4 -p resources/StagedFiles/devicetree.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()

    so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/kernel.img4 -p resources/StagedFiles/kernel.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()

    so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/trustcache.img4 -p resources/StagedFiles/trustcache.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()

    if A10A11Check:

        so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/aopfw.img4 -p resources/StagedFiles/aopfw.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()

        so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/isp.img4 -p resources/StagedFiles/isp.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()

        so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/callan.img4 -p resources/StagedFiles/callan.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()

        so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/touch.img4 -p resources/StagedFiles/touch.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()


def patchFiles(iOSVersion):
    if os.path.isfile("resources/kernel.im4p"):
        print("Patching Kernel's type from krnl to rkrn")
        with open("resources/kernel.im4p", "r+b") as fh:
            file = fh.read()
            try:
                offset = hex(file.index(b"\x6b\x72\x6e\x6c"))  # getting offset for tag krnl tag, can be 1 or 2 bytes off depending on the kernel
                offset = int(offset, 16)
                fh.seek(offset, 0)
                fh.write(b"\x72\x6b\x72\x6e")  # writing rkrn tag so we can boot =)
                fh.close()
            except:
                print("Kernel patching failed!")
                exit(2)
    if "11." in iOSVersion:
        print("iOS version is 11.x, skipping trustcache patching")
        pass
    elif "10." in iOSVersion:
        print("iOS version is 10.x, skipping trustcache patching")
        pass
    else:
        if os.path.exists("resources/StagedFiles/trustcache.im4p"):
            print("Patching TrustCache's type from trst to rtsc")
            with open("resources/StagedFiles/trustcache.im4p", "r+b") as fh:
                file = fh.read()
                try:
                    offset = hex(file.index(b"\x74\x72\x73\x74"))  # getting offset for tag trst tag, can be 1 or 2 bytes off depending on the trustcache
                    offset = int(offset, 16)
                    fh.seek(offset, 0)
                    fh.write(b'\x72\x74\x73\x63')  # writing rtsc tag so we can boot =)
                    fh.close()
                except:
                    print("Trustcache patching failed!")
                    exit(2)
        else:
            print("Error: Couldn't find resources/StagedFiles/trustcache.im4p, patching failed")
            exit(2)
    if os.path.exists("resources/StagedFiles/devicetree.im4p"):
        print("Patching Devicetree's type from dtre to rdtr")
        with open("resources/StagedFiles/devicetree.im4p", "r+b") as fh:
            file = fh.read()
            try:
                offset = hex(file.index(b"\x64\x74\x72\x65"))  # getting offset for tag dtre tag, can be 1 or 2 bytes off depending on the devicetree
                offset = int(offset, 16)
                fh.seek(offset, 0)
                fh.write(b'\x72\x64\x74\x72')  # writing rdtr tag so we can boot =)
                fh.close()
            except:
                print("Devicetree patching failed!")
                exit(2)


def sendImages(iosVersion, useCustomLogo, A10A11Check):
    #print("Sending boot files to the device and booting")
    if os.path.exists("resources"):
        os.chdir("resources")
    elif os.path.exists("LICENSE"):
        os.chdir("..")
    else:
        pass
    time.sleep(1)

    # This section removes signature checking
    try:
        cmd = "python2 ipwndfu8012/nop_image4.py"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(3)
    except:
        print("looks like signature removal failed. Trying one more time before giving up")
        try:
                    cmd = "python2 ipwndfu8012/nop_image4.py"
                    so = subprocess.Popen(cmd, shell=True)
        except:
            print("Signature removal failed! Please re-run this tool. If this problem persists please report it.")
            exit(2)

    cmd = "pwd"
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(0)

    #cmd = "bin/irecovery -f shsh.shsh"
    #so = subprocess.Popen(cmd, shell=True)
    #time.sleep(2)

    print("iBSS sent! Device should be booting into recovery")
    cmd = "bin/irecovery -f StagedFiles/ibss.pwn"
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(5)

    #For Testing Only!
    #cmd = "bin/irecovery2 -s"
    #so = subprocess.Popen(cmd, shell=True)

    print("iBEC sent! Device should initializing iBEC")
    cmd = "bin/irecovery -f StagedFiles/ibec.img4"
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(5)

    if A10A11Check:
        print("A10/A11 Check resolves to true")
        cmd = "bin/irecovery -f StagedFiles/ibec.img4"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(3)

        cmd = "bin/irecovery -c go"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(6)

    print("Bootx command send. This is needed to prevent Devicetree related issues later on")
    cmd = 'bin/irecovery -c "bootx"'  # Is needed to prevent Devicetree related issues later on
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(5)

    cmd = f"bin/irecovery -f StagedFiles/bootlogo.img4"
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(2)

    cmd = 'bin/irecovery -c "setpicture 0"'
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(2)

    cmd = 'bin/irecovery -c "bgcolor 0 0 0"'
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(2)

    print("Stopping here as this is all we have implemented!")
    input()

    cmd = "bin/irecovery -f StagedFiles/devicetree.img4"
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(2)

    cmd = 'bin/irecovery -c "devicetree"'
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(2)

    if A10A11Check:
        cmd = "bin/irecovery -f StagedFiles/aopfw.img4"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        cmd = "bin/irecovery -c firmware"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        cmd = "bin/irecovery -f StagedFiles/isp.img4"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        cmd = "bin/irecovery -c firmware"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        cmd = "bin/irecovery -f StagedFiles/callan.img4"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        cmd = "bin/irecovery -c firmware"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        cmd = "bin/irecovery -f StagedFiles/touch.img4"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        cmd = "bin/irecovery -c firmware"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)


    if not '11.' in iosVersion:  # 11.x and lower don't need trustcache sent to boot =)

        cmd = "bin/irecovery -f StagedFiles/trustcache.img4"
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

        cmd = 'bin/irecovery -c "firmware"'
        so = subprocess.Popen(cmd, shell=True)
        time.sleep(2)

    cmd = "bin/irecovery -f StagedFiles/kernel.img4"
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(2)

    cmd = 'bin/irecovery -c "bootx"'
    so = subprocess.Popen(cmd, shell=True)
    time.sleep(2)

    os.chdir("../")


def img4stuff(deviceModel, iOSVersion, useCustomLogo, bootlogoPath, areWeLocal, bootOtherOS, bootArgs, amfiPatches, devicemaplinematch):

    if deviceModel == "iPhone10,1" or deviceModel == "iPhone10,2" or deviceModel == "iPhone10,3" or deviceModel == "iPhone10,4" or deviceModel == "iPhone10,5" or deviceModel == "iPhone10,6" or deviceModel == "iPhone9,1" or deviceModel == "iPhone9,2" or deviceModel == "iPhone9,3" or deviceModel == "iPhone9,4" or deviceModel == "iBridge2,5":
        A10A11Check = True
    else:
        A10A11Check = False 

    api = ipswapi.APIParser(deviceModel, iOSVersion)

    """
    print(f"Checking theiphonewiki for {iOSVersion} keys...")
    wiki = iphonewiki.iPhoneWiki(deviceModel, iOSVersion)
    keys = wiki.getWikiKeys()
    if 'failed' in keys:
        print("Keys weren't found for your device, PyBoot will place your device into PWNDFU mode and retrieve the needed keys...\n")
        print("Please ensure your device is connected in DFU mode...")
        time.sleep(1)
        pwndfumodeKeys()
        needKeys = True
    else:

        needKeys = False

        iBECName = keys["IBEC"]
        iBECKey = keys["IBECKEY"]
        iBECIV = keys["IBECIV"]

        iBSSName = keys["IBSS"]
        iBSSKey = keys["IBSSKEY"]
        iBSSIV = keys["IBSSIV"]
        if iBECIV == "Unknown":  # Just making sure that there is keys, some key pages have keys for one model but not the other which could cause issues
            print("Keys for the other device model are present but not for your model.\nPyBoot will place your device into PWNDFU mode and retrieve the needed keys...")
            print("Please ensure your device is connected in DFU mode...")
            time.sleep(1)
        """
    pwndfumodeKeys()
    needKeys = True

    # geting shsh
    modelAP = ''

    if areWeLocal == False:
        print(f"Downloading {iOSVersion}'s BuildManifest.plist")
        try:
            api.downloadFileFromArchive("BuildManifest.plist", "resources/manifest.plist")
        except:
            print("Failed to retrieve BuildManifest on first try.. Restarting script should fix this problem. Restarting now..")
            try:
                #Hacky way of restarting the script when the BuildManifest Doesn't retrieve the first time.. 
                path_parent = os.path.dirname(os.getcwd())
                twolevels = os.path.dirname(path_parent)
                #print(f"python3 {path_parent}/odts.py " + f"{sys.argv[1]} {sys.argv[2]} {sys.argv[3]}")
                fallbackpath = path_parent + "/odts.py"
                fullpath = twolevels + "/odts.py"
                #print(fullpath)
                sys.stdout.flush()
                test1 = os.path.exists(fullpath)
                test2 = os.path.exists(fallbackpath)
                print (f"test 1: {test1} at {fullpath}")
                print (f"test 2: {test2} at {fallbackpath}")
                if os.path.exists(fullpath):
                    print(fullpath + "exists")
                    os.chdir(twolevels)
                    os.execl(sys.executable, 'python3', fullpath, *sys.argv[1:])
                if os.path.exists(fallbackpath):
                    print(fallbackpath + "exists")
                    os.chdir(path_parent)
                    os.execl(sys.executable, 'python3', fallbackpath, *sys.argv[1:])
                if os.path.exists(os.getcwd() + "/odts.py"):
                    print("odts.py exists in this directory")
                    print("Restarting script in current directory...")
                    os.execl(sys.executable, 'python3', os.getcwd() + "/odts.py", *sys.argv[1:])
                input()
                #cmd = f"python3 {path_parent}/odts.py {args.ios[1]} {args.ios[0]}"
                #so = subprocess.Popen(cmd, shell=True) 
            except:
                #print("\nUnable to retrieve BuildManifest Re-running the tool again should fix this problem.\nIf the device fails more than 4 times pleae power cycle it back into DFU mode and try again. Exiting for now..")
                exit(2)
    else:
        if os.path.exists("IPSW/BuildManifest.plist"):
            shutil.move("IPSW/BuildManifest.plist", "resources/manifest.plist")
        else:
            sys.exit("ERROR: Couldn't find local BuildManifest")
    if needKeys:
        line_number = 0
        num_lines = sum(1 for line in open('./resources/manifest.plist'))
        save_value = False
        models = []

        with open("./resources/manifest.plist", mode="rt") as read_plist:

            while line_number < num_lines:

                for line in read_plist:
                    
                    if save_value:

                        apModel = line.rstrip()

                        if not apModel in models:

                            models.append(apModel)

                        save_value = False

                    if re.search("DeviceClass", line):
                        save_value = True

                    line_number += 1
        read_plist.close()

        length = len(models) 
        i = 0

        while i < length: 
            temp_name = models[i]
            str(temp_name.strip('\t\t\t'))
            temp_name = temp_name[12:-9]
            models[i] = temp_name
            i += 1

        #print(f"Found multiple device models...\nWhich is your device?\n")
        length = 1 
        i = 0

        while i < length:
            #print(f"{i + 1}: {models[i]}")
            i += 1
        #modelchoice = input("\nEnter the number that corresponds with your device: ")
        #if (int(modelchoice) - 1) <= length and int(modelchoice) > 0:
            #print(f"Device set to {models[int(modelchoice) - 1]}")
            modelAP = devicemaplinematch
            print(f"Device set to {modelAP}")
            ibxxName = False
            firmwareName = []
            line_number = 0
            with open("./resources/manifest.plist", mode="rt") as read_plist:

                while line_number < num_lines:

                    for line in read_plist:
                        
                        if ibxxName:
                            temp = line.rstrip()
                            if re.search("<string>Firmware/dfu/iBEC", temp):
                                str(temp.strip('\t\t\t'))
                                temp = temp[27:-9]
                                firmwareName.append(temp)
                                line_number = num_lines + 1
                                ibxxName = False
                                break

                        if save_value:

                            apModel = line.rstrip()
                            str(apModel.strip('\t\t\t'))
                            apModel = apModel[12:-9]
                            if modelAP == apModel:
                                ibxxName = True
                            save_value = False

                        if re.search("DeviceClass", line):
                            save_value = True

                        line_number += 1
            read_plist.close()
            modelAP = modelAP
            iBECName = firmwareName[0]
            iBSSName = iBECName.replace("iBEC", "iBSS")
            print(iBECName)
            print(iBSSName)
        #else:
            #print("Error: Invalid input, Exiting...")
            #exit(0)

    if modelAP == '':
        line_number = 0
        num_lines = sum(1 for line in open('./resources/manifest.plist'))
        save_value = False
        models = []

        with open("./resources/manifest.plist", mode="rt") as read_plist:

            while line_number < num_lines:

                for line in read_plist:
                    
                    if save_value:

                        apModel = line.rstrip()

                        if not apModel in models:

                            models.append(apModel)

                        save_value = False

                    if re.search("DeviceClass", line):
                        save_value = True

                    line_number += 1
        read_plist.close()

        length = len(models) 
        i = 0

        while i < length: 
            temp_name = models[i]
            str(temp_name.strip('\t\t\t'))
            temp_name = temp_name[12:-9]
            models[i] = temp_name
            i += 1

        #print(f"Found multiple device models...\nWhich is your device?\n")
        #length = len(models) 
        #i = 0

        #while i < length:
            #print(f"{i + 1}: {models[i]}")
            #i += 1
        #modelchoice = input("\nEnter the number that corresponds with your device: ")
        #if (int(modelchoice) - 1) <= length and int(modelchoice) > 0:
            #print(f"Device set to {models[int(modelchoice) - 1]}")
            modelAP = devicemaplinematch
            print (modelAP)
            input()
        else:
            print("Error: Invalid input, Exiting...")
            exit(0)


    modelAP = devicemaplinematch

    print("Getting SHSH for signing images")

    # We need to get SHSH for A11 devices using the current device model otherwise it will not boot :/
    if (deviceModel == "iPhone10,3"):
        tssmodel = "iPhone10,3"
    elif (deviceModel == "iPhone10,6"):
        tssmodel = "iPhone10,6"
    elif (deviceModel == "iPhone10,1"):
        tssmodel = "iPhone10,1"
    elif (deviceModel == "iPhone10,2"):
        tssmodel = "iPhone10,2"
    elif (deviceModel == "iPhone10,4"):
        tssmodel = "iPhone10,4"
    elif (deviceModel == "iPhone10,5"):
        tssmodel = "iPhone10,5"
    elif (deviceModel == "iPhone9,1"):
        tssmodel = "iPhone9,1"
    elif (deviceModel == "iPhone9,2"):
        tssmodel = "iPhone9,2"
    elif (deviceModel == "iPhone9,3"):
        tssmodel = "iPhone9,3"
    elif (deviceModel == "iPhone9,4"):
        tssmodel = "iPhone9,4"
    else:
        tssmodel = "iPhone6,2" # iPhone6,2 seems to work for all non-A11 device, if not let me know

    text = str(dfu.acquire_device())
    text[text.find(start:='ECID:')+len(start):text.find(' IBFL:')]
    ecid = str(text[text.find(start:='ECID:')+len(start):text.find(' IBFL:')])
    print(f"{ecid}")
    #print("Please check if ECID is correct")
    #input()

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
        pass
    else:
        sys.exit("ERROR: Failed to save shsh")

    if areWeLocal == False:

        print(f"Downloading and patching {iOSVersion}'s iBSS/iBEC")

        api.downloadFileFromArchive(f"Firmware/dfu/{iBECName}", "resources/StagedFiles/ibec.im4p")
        api.downloadFileFromArchive(f"Firmware/dfu/{iBSSName}", "resources/StagedFiles/ibss.im4p")
        test = False
    else:
        # We need to move the correct iBSS/iBEC from IPSW/ to resources/
        print("Moving iBSS/iBEC...")
        shutil.move(f"IPSW/{iBECName}", "resources/StagedFiles/ibec.im4p")
        shutil.move(f"IPSW/{iBSSName}", "resources/StagedFiles/ibss.im4p")

    if needKeys:

        so = subprocess.Popen("./resources/bin/img4tool -a resources/StagedFiles/ibss.im4p", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()
        output = output.decode("utf-8")
        offset1 = output.find("num: 1")
        offset2 = output.find("num: 2")
        offset1 += 7
        iBSSKBAG = output[offset1:offset2]
        iBSSKBAG = iBSSKBAG.strip('\n')
        iBSSKBAG = iBSSKBAG[0 : 32 : ] + iBSSKBAG[32 + 1 : :]

        so = subprocess.Popen("./resources/bin/img4tool -a resources/StagedFiles/ibec.im4p", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()
        output = output.decode("utf-8")

        offset1 = output.find("num: 1")
        offset2 = output.find("num: 2")
        offset1 += 7
        iBECKBAG = output[offset1:offset2]
        iBECKBAG = iBECKBAG.strip(  '\n')
        iBECKBAG = iBECKBAG[0 : 32 : ] + iBECKBAG[32 + 1 : :]

        print(f"iBSSKBAG is {iBSSKBAG}")
        print(f"iBECKBAG is {iBECKBAG}")
        #print("Waiting for user to press enter...")
        #input()

        ibssIVKEY = decryptKBAG(iBSSKBAG)
        ibecIVKEY = decryptKBAG(iBECKBAG)

        if len(ibssIVKEY) != 96 or len(ibecIVKEY) != 96:
            print(ibssIVKEY)
            print(ibecIVKEY)
            sys.exit('String provided is not 96 bytes!')
        else:
            iBSSIV = ibssIVKEY[:32]
            iBSSKey = ibssIVKEY[-64:]
            iBECIV = ibecIVKEY[:32]
            iBECKey = ibecIVKEY[-64:]

        #print("\n\nDevice needs to be rebooted in order to continue, please re-enter DFU mode and then press enter to continue...")
        #print("If you do not reboot the device into DFU mode, PyBoot will fail to send the needed boot components")
        #print("Waiting for user to press enter...")
        #input()

    #check if bootargs string is empty if it is replace it with "rd=md0 -restore -v"
    print(f"Boot arguments for iBec set to {bootArgs}")
    patcher = "kairos" # Just allows me to change what boot image patcher I use with ease (mainly for A11 tests)
    if (deviceModel == "iPhone10,1" or deviceModel == "iPhone10,2" or deviceModel == "iPhone10,3" or deviceModel == "iPhone10,4" or deviceModel == "iPhone10,5" or deviceModel == "iPhone10,6"):
        patcher = "iBoot64Patcher"
        #print("A11 or T2 detected, using iBoot64Patcher...")
    so = subprocess.Popen(f"./resources/bin/img4tool -e -o resources/StagedFiles/ibss.raw --iv {iBSSIV} --key {iBSSKey} resources/StagedFiles/ibss.im4p", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()    
    if useCustomLogo:
        if bootOtherOS:
            so = subprocess.Popen(f'./resources/bin/{patcher} resources/StagedFiles/ibss.raw resources/StagedFiles/ibss.pwn -b "{bootArgs}"', stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
        else:
            so = subprocess.Popen(f'./resources/bin/{patcher} resources/StagedFiles/ibss.raw resources/StagedFiles/ibss.pwn', stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
    else:
        so = subprocess.Popen(f'./resources/bin/{patcher} resources/StagedFiles/ibss.raw resources/StagedFiles/ibss.pwn -b "{bootArgs}"', stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()

    so = subprocess.Popen(f"./resources/bin/img4tool -e -o resources/StagedFiles/ibec.raw --iv {iBECIV} --key {iBECKey} resources/StagedFiles/ibec.im4p", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()
    if useCustomLogo:
        if bootOtherOS:
            so = subprocess.Popen(f'./resources/bin/{patcher} resources/StagedFiles/ibec.raw resources/StagedFiles/ibec.pwn -b "{bootArgs}"', stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
        else:
            so = subprocess.Popen(f'./resources/bin/{patcher} resources/StagedFiles/ibec.raw resources/StagedFiles/ibec.pwn', stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
    else:
        so = subprocess.Popen(f'./resources/bin/{patcher} resources/StagedFiles/ibec.raw resources/StagedFiles/ibec.pwn -b "{bootArgs}"', stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()
    if bootOtherOS and "13." in iOSVersion:
        # Excuse the long byte strings, just want to be sure that we patch the correct thing :)

        # This conversion from bootarg to byte was a nightware to get working -_- needed to be done though for full 13.x dualbooting support
        # Glad its over. Basically it will take the last char from your disk0s1sX and convert it to a value that can be written to ibec 
        length = len(bootArgs)
        last_char = bootArgs[length -1]
        last_char = str(int(last_char) - 1)
        last_char = format((ord(last_char)), "x")

        bootpartitionString = b"\x30\x00\x2F\x53\x79\x73\x74\x65\x6D\x2F\x4C\x69\x62\x72\x61\x72\x79\x2F\x43\x61\x63\x68\x65\x73\x2F\x63\x6F\x6D\x2E\x61\x70\x70\x6C\x65\x2E\x6B\x65\x72\x6E\x65\x6C\x63\x61\x63\x68\x65\x73\x2F\x6B\x65\x72\x6E\x65\x6C\x63\x61\x63\x68\x65"
        bootpartitionPatch = bytes([int(last_char) + 18]) # Only way I found to get the users disk from a string, to an int -1, back to a string, then to hex minus the 0x,
                                                          # then to an int then to that int + 18 to be a byte value that will actually write and work
                                                          # This needed to be added though, as some 13.x devices will have SystemB as disk0s1s7 not always disk0s1s6 as I had hardcoded before
        if os.path.isfile("resources/ibec.pwn"):
            print("Patching boot-partition in iBEC")
            with open("resources/ibec.pwn", "r+b") as fh:
                file = fh.read()
                try:
                    offset = hex(file.index(bootpartitionString))  # getting offset for start of string
                    offset = int(offset, 16)
                    fh.seek(offset, 0)
                    fh.write(bootpartitionPatch)  # writing the disk0s1sX value to iBEC
                    fh.close()
                    print("boot-partition patch complete")
                except:
                    print("iBEC patching failed!")
                    exit(2)

    so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/ibec.patched -t ibec resources/StagedFiles/ibec.pwn", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()

    so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/ibss.patched -t ibss resources/StagedFiles/ibss.pwn", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()

    so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/ibss.img4 -p resources/StagedFiles/ibss.patched -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()

    so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/ibec.img4 -p resources/StagedFiles/ibec.patched -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()

    so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/ramdisk.img4 -p resources/018-75901-013.dmg -t rdsk -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
    output = so.stdout.read()

    if useCustomLogo:
        # Now need to convert the .PNG to a img4 format to use while booting

        if str(bootlogoPath).lower().endswith(".png"):
            so = subprocess.Popen(f"./resources/bin/ibootim {bootlogoPath} resources/StagedFiles/bootlogo.ibootim", stdout=subprocess.PIPE, shell=True)  # Thanks to realnp for ibootim!
            output = so.stdout.read()
            # now create im4p
            so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/bootlogo.im4p -t logo resources/StagedFiles/bootlogo.ibootim", stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
            # Add signature from shsh
            so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/bootlogo.img4 -p resources/StagedFiles/bootlogo.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
            bootlogoPath = "resources/StagedFiles/bootlogo.img4"
        else:
            print("Please provide a .png file, other image types are not supported")
            exit(2)
    else:
        if (os.path.exists("resources/bootlogo.png")):
            so = subprocess.Popen(f"./resources/bin/ibootim resources/StagedFiles/bootlogo.png resources/StagedFiles/bootlogo.ibootim", stdout=subprocess.PIPE, shell=True)  # Thanks to realnp for ibootim!
            output = so.stdout.read()
            # now create im4p
            so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/bootlogo.im4p -t logo resources/StagedFiles/bootlogo.ibootim", stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
            # Add signature from shsh
            so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/bootlogo.img4 -p resources/StagedFiles/bootlogo.im4p -s resources/shsh.shsh", stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
            bootlogoPath = "resources/StagedFiles/bootlogo.img4"
        else:
            print("Please either add your own image to ./resources/StagedFiles/bootlogo.png or redownload the one that comes with ODTS")
            exit(0)


    # iBSS/iBEC stuff is done, we now need to get devicetree, trustcache and kernel

    line_number = 0
    num_lines = sum(1 for line in open('./resources/manifest.plist'))
    kernSave = False
    kernelname = ""
    save_value = False

    with open("./resources/manifest.plist", mode="rt") as read_plist:

        while line_number < num_lines:

            for line in read_plist:
                
                if kernSave:
                    temp = line.rstrip()
                    if re.search("<string>kernelcache.release.", temp):
                        str(temp.strip('\t\t\t'))
                        temp = temp[14:-9]
                        kernelname = temp
                        line_number = num_lines + 1
                        kernSave = False
                        break

                if save_value:

                    deviceModel = line.rstrip()
                    str(deviceModel.strip('\t\t\t'))
                    deviceModel = deviceModel[12:-9]
                    if modelAP == deviceModel:
                        kernSave = True
                    save_value = False

                if re.search("DeviceClass", line):
                    save_value = True

                line_number += 1
    read_plist.close()

    if areWeLocal == False:

        print(f"Downloading {iOSVersion}'s KernelCache")
        try:
            api.downloadFileFromArchive(kernelname, "resources/StagedFiles/kernel.im4p")
        except:
            print("ERROR: Failed to download Kernel\nPlease re-run PyBoot again and it should work (might take a few tries)")
            exit(2)
    else:
        if os.path.exists(f"IPSW/{kernelname}"):
            shutil.move(f"IPSW/{kernelname}", "resources/StagedFiles/kernel.im4p")
        else:
            sys.exit("ERROR: Couldn't find local kernelcache")
    if amfiPatches:
        print("Applying AMFI patches to kernel (Thanks to Ralph and mcg29_)")
        so = subprocess.Popen(f"./resources/bin/img4 -i resources/StagedFiles/kernel.im4p -o resources/StagedFiles/kernel.raw", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()
        time.sleep(5)
        if os.path.exists("resources/StagedFiles/kernel.raw"):
            print("Saved raw kernel to 'resources/StagedFiles/kernel.raw'")
            so = subprocess.Popen(f"./resources/bin/Kernel64Patcher resources/StagedFiles/kernel.raw resources/StagedFiles/kernel.patched -a", stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
            patchThing()
            print("Patched AMFI from kernel")            
            so = subprocess.Popen(f"./resources/bin/img4tool -e -s resources/shsh.shsh -m resources/IM4M", stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
            so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/kernel.im4p -t rkrn resources/StagedFiles/kernel.patched", stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()
            so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/kernel.img4 -p resources/StagedFiles/kernel.im4p -m ../IM4M", stdout=subprocess.PIPE, shell=True)
            output = so.stdout.read()                        
            print("Finished patching kernel!\nContinuing with PyBoot...\n")
        else:
            print("Failed to extract raw kernel, continuing without AMFI kernel patches...")

    line_number = 0
    num_lines = sum(1 for line in open('./resources/manifest.plist'))
    dtreeSave = False
    devicetreename = ""
    save_value = False

    with open("./resources/manifest.plist", mode="rt") as read_plist:

        while line_number < num_lines:

            for line in read_plist:
                
                if dtreeSave:
                    temp = line.rstrip()
                    if re.search("<string>Firmware/all_flash/DeviceTree", temp):
                        str(temp.strip('\t\t\t'))
                        temp = temp[33:-9]
                        devicetreename = temp
                        line_number = num_lines + 1
                        dtreeSave = False
                        break

                if save_value:

                    deviceModel = line.rstrip()
                    str(deviceModel.strip('\t\t\t'))
                    deviceModel = deviceModel[12:-9]
                    if modelAP == deviceModel:
                        dtreeSave = True
                    save_value = False

                if re.search("DeviceClass", line):
                    save_value = True

                line_number += 1
    read_plist.close()

    if areWeLocal == False:

        print(f"Downloading {iOSVersion}'s DeviceTree")
        try:
            api.downloadFileFromArchive(f"Firmware/all_flash/{devicetreename}", "resources/StagedFiles/devicetree.im4p")
        except:
            print("ERROR: Failed to download DeviceTree\nPlease re-run PyBoot again and it should work (might take a few tries)")
            exit(2)
    else:
        if os.path.exists(f"IPSW/Firmware/all_flash/{devicetreename}"):
            shutil.move(f"IPSW/Firmware/all_flash/{devicetreename}", "resources/StagedFiles/devicetree.im4p")
        else:
            sys.exit("ERROR: Couldn't find local devicetree")

    if bootOtherOS and "13." in iOSVersion:

        print("Patching Devicetree to allow for new Data partition to be mounted (13.x Only)...")
        # Unpack devicetree so Ralph's patcher will work
        so = subprocess.Popen(f"./resources/bin/img4tool -e -o resources/StagedFiles/devicetree.raw resources/StagedFiles/devicetree.im4p", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()
        # Patch it
        so = subprocess.Popen(f"./resources/bin/dtree_patcher resources/StagedFiles/devicetree.raw resources/StagedFiles/devicetree.patched -d", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()
        # Repack it to im4p
        so = subprocess.Popen(f"./resources/bin/img4tool -c resources/StagedFiles/devicetree.im4p -t dtre resources/StagedFiles/devicetree.patched", stdout=subprocess.PIPE, shell=True)
        output = so.stdout.read()

    line_number = 0
    num_lines = sum(1 for line in open('./resources/manifest.plist'))
    tcachesave = False
    trustcachename = ""
    save_value = False
    tcache = False

    with open("./resources/manifest.plist", mode="rt") as read_plist:

        while line_number < num_lines:

            for line in read_plist:

                if tcache:
                    temp = line.rstrip()
                    if re.search("<string>Firmware/", temp):
                        str(temp.strip('\t\t\t'))
                        temp = temp[23:-9]
                        trustcachename = temp
                        line_number = num_lines + 1
                        tcache = False
                        break
                
                if tcachesave:
                    temp = line.rstrip()
                    if re.search("<key>StaticTrustCache</key>", temp):
                        tcachesave = False
                        tcache = True

                if save_value:

                    deviceModel = line.rstrip()
                    str(deviceModel.strip('\t\t\t'))
                    deviceModel = deviceModel[12:-9]
                    if modelAP == deviceModel:
                        tcachesave = True
                    save_value = False

                if re.search("DeviceClass", line):
                    save_value = True

                line_number += 1
    read_plist.close()

    if areWeLocal == False:

        if '11.' in iOSVersion:
            print("iOS version is 11.x, not downloading trustcache")
            pass
        elif '10.' in iOSVersion:
            print("iOS version is 10.x, not downloading trustcache")
            pass
        else:

            print(f"Downloading {iOSVersion}'s TrustCache")
            try:
                api.downloadFileFromArchive(f'Firmware/{trustcachename}', "resources/StagedFiles/trustcache.im4p")
            except:
                print("ERROR: Failed to download TrustCache\nPlease re-run PyBoot again and it should work (might take a few tries)")
                exit(2)
            time.sleep(5)
    else:
        
        if os.path.exists(f"IPSW/Firmware/{trustcachename}"):
            shutil.move(f"IPSW/Firmware/{trustcachename}", "resources/StagedFiles/trustcache.im4p")
        else:
            sys.exit("ERROR: Couldn't find local trustcache")

    if A10A11Check:

        # aopfw download 

        print(f"Downloading {iOSVersion}'s AOPFW")

        line_number = 0
        num_lines = sum(1 for line in open('./resources/manifest.plist'))
        aopfwSave = False
        aopfwName = ""
        save_value = False


        with open("./resources/manifest.plist", mode="rt") as read_plist:

            while line_number < num_lines:

                for line in read_plist:
                    
                    if aopfwSave:
                        temp = line.rstrip()
                        if re.search("<string>Firmware/AOP/", temp):
                            str(temp.strip('\t\t\t'))
                            temp = temp[27:-9]
                            aopfwName = temp
                            line_number = num_lines + 1
                            aopfwSave = False
                            break

                    if save_value:

                        deviceModel = line.rstrip()
                        str(deviceModel.strip('\t\t\t'))
                        deviceModel = deviceModel[12:-9]
                        if modelAP == deviceModel:
                            aopfwSave = True
                        save_value = False

                    if re.search("DeviceClass", line):
                        save_value = True

                    line_number += 1
        read_plist.close()

        try:
            api.downloadFileFromArchive(f'Firmware/AOP/{aopfwName}', "resources/StagedFiles/aopfw.im4p")
        except:
            print("ERROR: Failed to download AOPFW\nPlease re-run PyBoot again and it should work (might take a few tries)")
            exit(2)

        # ISP download 

        print(f"Downloading {iOSVersion}'s ISP")

        line_number = 0
        num_lines = sum(1 for line in open('./resources/manifest.plist'))
        ispSave = False
        ispName = ""
        save_value = False


        with open("./resources/manifest.plist", mode="rt") as read_plist:

            while line_number < num_lines:

                for line in read_plist:
                    
                    if ispSave:
                        temp = line.rstrip()
                        if re.search("<string>Firmware/isp_bni/", temp):
                            str(temp.strip('\t\t\t'))
                            temp = temp[31:-9]
                            ispName = temp
                            line_number = num_lines + 1
                            ispSave = False
                            break

                    if save_value:

                        deviceModel = line.rstrip()
                        str(deviceModel.strip('\t\t\t'))
                        deviceModel = deviceModel[12:-9]
                        if modelAP == deviceModel:
                            ispSave = True
                        save_value = False

                    if re.search("DeviceClass", line):
                        save_value = True

                    line_number += 1
        read_plist.close()

        try:
            api.downloadFileFromArchive(f'Firmware/isp_bni/{ispName}', "resources/StagedFiles/isp.im4p")
        except:
            print("ERROR: Failed to download ISP")
            #exit(2)

        # Callan download 

        print(f"Downloading {iOSVersion}'s CallanFirmware")

        line_number = 0
        num_lines = sum(1 for line in open('./resources/manifest.plist'))
        callanSave = False
        callanName = ""
        save_value = False


        with open("./resources/manifest.plist", mode="rt") as read_plist:

            while line_number < num_lines:

                for line in read_plist:
                    
                    if callanSave:
                        temp = line.rstrip()
                        if re.search("CallanFirmware.im4p</string>", temp):
                            str(temp.strip('\t\t\t'))
                            temp = temp[23:-9]
                            callanName = temp
                            line_number = num_lines + 1
                            callanSave = False
                            break

                    if save_value:

                        deviceModel = line.rstrip()
                        str(deviceModel.strip('\t\t\t'))
                        deviceModel = deviceModel[12:-9]
                        if modelAP == deviceModel:
                            callanSave = True
                        save_value = False

                    if re.search("DeviceClass", line):
                        save_value = True

                    line_number += 1
        read_plist.close()

        try:
            api.downloadFileFromArchive(f'Firmware/{callanName}', "resources/StagedFiles/callan.im4p")
        except:
            print("ERROR: Failed to download CallanFirmware.. Skipping this for now. Might be required but we are in diagnostic..")
            #exit(2)

        # MultiTouch download 

        print(f"Downloading {iOSVersion}'s MultiTouch Firmware")

        line_number = 0
        num_lines = sum(1 for line in open('./resources/manifest.plist'))
        touchSave = False
        touchName = ""
        save_value = False


        with open("./resources/manifest.plist", mode="rt") as read_plist:

            while line_number < num_lines:

                for line in read_plist:
                    
                    if touchSave:
                        temp = line.rstrip()
                        if re.search("Multitouch.im4p</string>", temp):
                            str(temp.strip('\t\t\t'))
                            temp = temp[23:-9]
                            touchName = temp
                            line_number = num_lines + 1
                            touchSave = False
                            break

                    if save_value:

                        deviceModel = line.rstrip()
                        str(deviceModel.strip('\t\t\t'))
                        deviceModel = deviceModel[12:-9]
                        if modelAP == deviceModel:
                            touchSave = True
                        save_value = False

                    if re.search("DeviceClass", line):
                        save_value = True

                    line_number += 1
        read_plist.close()

        try:
            api.downloadFileFromArchive(f'Firmware/{touchName}', "resources/StagedFiles/touch.im4p")
        except:
            print("ERROR: Failed to download MultiTouch Firmware\nPlease re-run PyBoot again and it should work (might take a few tries)")
            exit(2)

       # Stockholm Download 

        print(f"Downloading {iOSVersion}'s Stockholm Firmware")

        line_number = 0
        num_lines = sum(1 for line in open('./resources/manifest.plist'))
        touchSave = False
        touchName = ""
        save_value = False


        with open("./resources/manifest.plist", mode="rt") as read_plist:

            while line_number < num_lines:

                for line in read_plist:
                    
                    if touchSave:
                        temp = line.rstrip()
                        if re.search("RELEASE.sefw</string>", temp):
                            str(temp.strip('\t\t\t'))
                            temp = temp[23:-9]
                            stockholmName = temp
                            line_number = num_lines + 1
                            touchSave = False
                            break

                    if save_value:

                        deviceModel = line.rstrip()
                        str(deviceModel.strip('\t\t\t'))
                        deviceModel = deviceModel[12:-9]
                        if modelAP == deviceModel:
                            touchSave = True
                        save_value = False

                    if re.search("DeviceClass", line):
                        save_value = True

                    line_number += 1
        read_plist.close()

        try:
            api.downloadFileFromArchive(f'Firmware/{stockholmName}', "resources/StagedFiles/stockholm.im4p")
        except:
            print("ERROR: Failed to download MultiTouch Firmware\nPlease re-run PyBoot again and it should work (might take a few tries)")
            exit(2)

    patchFiles(iOSVersion)
    signImages(A10A11Check)
