import os
import time
import re
from resources.ipwndfu import checkm8, dfu, usbexec 
from odtslib.config import PROJECT_ROOT
from odtslib.tool_wrappers import GenericBinaryTool, ToolRegistry

TOOLS = ToolRegistry()


def _run_repo_binary(name: str, relative_path: str, *args: str) -> str:
    tool = GenericBinaryTool(name, PROJECT_ROOT / relative_path)
    result = tool.execute(*args, cwd=PROJECT_ROOT)
    return result.stdout or result.stderr


def _run_python_tool(interpreter: str, script_path: str, *args: str) -> str:
    tool = GenericBinaryTool(interpreter, interpreter)
    result = tool.execute(PROJECT_ROOT / script_path, *args, cwd=PROJECT_ROOT)
    return result.stdout or result.stderr

def decryptKBAG(kbag: str):

    try:
        device = dfu.acquire_device()
    except:
        print("T2 device in dirty state. Please powercycle back into DFU mode and re-run this tool. Contact me if issue persists.")
        exit(2)
    serial_number = device.serial_number
    #print(f"serial number is {serial_number}")
    #print("\nWaiting for user to press enter...")
    dfu.release_device(device)
    if "CPID:8960" in serial_number or "CPID:8965" in serial_number or "CPID:8010" in serial_number or "CPID:8015" in serial_number:
        cmd = f'resources/ipwndfuX/ipwndfu --decrypt-gid={kbag}' # Tried to port the function to python3 but was far to difficult for some reason
    elif "CPID:8000" in serial_number or "CPID:8003" in serial_number or "CPID:7000" in serial_number or "CPID:7001" in serial_number:
        cmd = f'resources/ipwndfuKeys/ipwndfu --decrypt-gid={kbag}' # Tried to port the function to python3 but was far to difficult for some reason
    elif "CPID:8012" in serial_number:
        try:
            cmd = f'resources/ipwndfu8012/ipwndfu --decrypt-gid={kbag}' # Tried to port the function to python3 but was far to difficult for some reason 
        except:
            print("T2 device in dirty state. Please powercycle back into DFU mode and re-run this tool. Contact me if issue persists.")
            exit(2)   
    else:
        print("Not supported...")
        exit(0)
    tool_path = cmd.split()[0]
    tool_args = cmd.split()[1:]
    ivkey = _run_repo_binary("legacy-ipwndfu", tool_path, *tool_args)
    ivkey = re.sub(r'Decrypting with \w+ GID key\.', '', ivkey)
    ivkey = ivkey[1:-1]

    return ivkey

def pwndfumodeKeys():

    device = dfu.acquire_device()
    serial_number = device.serial_number
    dfu.release_device(device)

    if "CPID:8960" in serial_number:
        if not os.path.exists("checkm8.py"):
            os.chdir("resources/ipwndfu")
        runexploit = checkm8.exploit()
        if runexploit:
            os.chdir("../..")
        else:
            print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
            input()
            pwndfumodeKeys  ()
    elif "CPID:8965" in serial_number:
        if not os.path.exists("checkm8.py"):
            os.chdir("resources/ipwndfu")
        runexploit = checkm8.exploit()
        if runexploit:
            print("Exploit worked!")
            os.chdir("../..")
        else:
            print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
            input()
            pwndfumodeKeys()
    elif "CPID:8010" in serial_number:
        if "PWND:[checkm8]" in serial_number:
            print("Device already in PWNDFU mode, not re-running exploit..")
            return
        else:
            if not os.path.exists("checkm8.py"):
                os.chdir("resources/ipwndfu8010")
            cmd = './ipwndfu -p'
            so = _run_repo_binary("ipwndfu8010", "resources/ipwndfu8010/ipwndfu", "-p")
            print(so)
            if "ERROR: No Apple device" in so:
                print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
                input()
                pwndfumodeKeys()
            time.sleep(5)
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)
            if "PWND:[checkm8]" in serial_number:
                print("Exploit worked!")
                os.chdir("../..")
                time.sleep(5)
                return

    elif "CPID:8012" in serial_number:
        if "PWND:[checkm8]" in serial_number:
            print("Device already in PWNDFU mode, not re-running exploit..")
            return
        else:
            if not os.path.exists("checkm8.py"):
                os.chdir("resources/ipwndfu8012")
            cmd = './ipwndfu -p'
            so = _run_repo_binary("ipwndfu8012", "resources/ipwndfu8012/ipwndfu", "-p")
            print(so)
            time.sleep(5)
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)
            if "PWND:[checkm8]" in serial_number:
                print("Exploit worked! Not patching out signature checks")
                print(so) 

    elif "CPID:8015" in serial_number:
        if "PWND:[checkm8]" in serial_number:
            print("Device already in PWNDFU mode, not re-running exploit..")
            return
        else:
            if not os.path.exists("checkm8.py"):
                os.chdir("resources/ipwndfuX")
            cmd = './ipwndfu -p'
            so = _run_repo_binary("ipwndfuX", "resources/ipwndfuX/ipwndfu", "-p")
            print(so)
            if "ERROR: No Apple device" in so:
                print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
                input()
                pwndfumodeKeys()
            os.chdir("../..")
            time.sleep(5)
            # Need to re-acquire the device before we check if checkm8 worked or it will always report as failed
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)
            if "PWND:[checkm8]" in serial_number:
                print("Exploit worked!")
                return
            else:
                print("Exploit failed...\nReboot and try again...")
                exit(2)
    elif "CPID:8000" in serial_number or "CPID:8003" in serial_number or "CPID:7000" in serial_number or "CPID:7001" in serial_number:
        if "PWND:[checkm8]" in serial_number:
            print("Device already in PWNDFU mode, not re-running exploit..")
            return
        else:
            if not os.path.exists("checkm8.py"):
                os.chdir("resources/ipwndfuKeys")
            cmd = './ipwndfu -p'
            so = _run_repo_binary("ipwndfuKeys", "resources/ipwndfuKeys/ipwndfu", "-p")
            print(so)
            if "ERROR: No Apple device" in so:
                print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
                input()
                pwndfumodeKeys()
            os.chdir("../..")
            time.sleep(5)
            # Need to re-acquire the device before we check if checkm8 worked or it will always report as failed
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)
            if "PWND:[checkm8]" in serial_number:
                print("Exploit worked!")
                return
            else:
                print("Exploit failed...\nReboot and try again...")
                exit(2)               
        return
    else:
        print("Please open an issue and let me know what device you are using/it's CPID and I will add support ASAP")
        exit(2)


def pwndfumode():

    device = dfu.acquire_device()
    serial_number = device.serial_number
    dfu.release_device(device)

    if "CPID:8960" in serial_number:
        so = TOOLS.ipwnder32.execute("-p", cwd=PROJECT_ROOT).stdout
        
        if "Device is now in pwned DFU mode!" in so:
            print("Exploit worked!")
            return
        else:
            print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
            input()
            pwndfumode()

    elif "CPID:8965" in serial_number:
        if not os.path.exists("checkm8.py"):
            os.chdir("resources/ipwndfu")
        runexploit = checkm8.exploit()
        if runexploit:
            print("Exploit worked!")
            so = _run_python_tool("python2.7", "resources/ipwndfu/rmsigchks.py")
            print(so)
            os.chdir("../..")
        else:
            print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
            input()
            pwndfumode()
    elif "CPID:8010" in serial_number:
        if not os.path.exists("resources/Fugu_8010/Fugu"):
            print(
                "Missing legacy Fugu payload at resources/Fugu_8010/Fugu. "
                "Runtime auto-download was removed; install it manually before using CPID:8010 support."
            )
            exit(2)

        if "PWND:[checkm8]" in serial_number:
            print("Device already in PWNDFU mode, not re-running exploit..")
            return
        else:
            if not os.path.exists("Fugu"):
                os.chdir("resources/Fugu_8010")
            so = _run_repo_binary("Fugu", "resources/Fugu_8010/Fugu", "rmsigchks")
            #print(so)
            if "Exploiting iDevice: FAILED!" in so:
                print("Exploit failed, however re-expoilting without rebooting might work. Attempting now...")
                pwndfumode()
            if "Device could not be found!" in so:
                print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
                input()
                pwndfumode()
            time.sleep(5)
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)
            if "PWND:[checkm8]" in serial_number:
                print("Exploit worked!")
                os.chdir("../..")
                time.sleep(5)
                return

    elif "CPID:8012" in serial_number:
        if "PWND:[checkm8]" in serial_number:
            print("Device already in PWNDFU mode, not re-running exploit..")
            return
        else:
            if not os.path.exists("checkm8.py"):
                os.chdir("resources/ipwndfu8012")
            so = _run_repo_binary("ipwndfu8012", "resources/ipwndfu8012/ipwndfu", "-p")
            print(so)
            time.sleep(5)
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)
            if "PWND:[checkm8]" in serial_number:
                print("Exploit worked! patching out signature checks")
                so = _run_python_tool("python", "resources/ipwndfu8012/nop_image4.py")
                print(so)   


    elif "CPID:8015" in serial_number:
        if "PWND:[checkm8]" in serial_number:
            print("Device already in PWNDFU mode, not re-running exploit..")
            return
        else:
            if not os.path.exists("checkm8.py"):
                os.chdir("resources/ipwndfuX")
            so = _run_repo_binary("ipwndfuX", "resources/ipwndfuX/ipwndfu", "-p")
            print(so)
            if "ERROR: No Apple device" in so:
                print("Exploit failed, reboot device into DFU mode and press enter to re-run checkm8")
                input()
                pwndfumode()
            so = _run_repo_binary("ipwndfuX", "resources/ipwndfuX/ipwndfu", "--patch")
            print(so)
            os.chdir("../..")
            time.sleep(5)
            # Need to re-acquire the device before we check if checkm8 worked or it will always report as failed
            device = dfu.acquire_device()
            serial_number = device.serial_number
            dfu.release_device(device)
            if "PWND:[checkm8]" in serial_number:
                print("Exploit worked!")
                return
            else:
                print("Exploit failed...\nReboot and try again...")
                exit(2)
    elif "CPID:8000" in serial_number:
        so = TOOLS.eclipsa8000.execute(cwd=PROJECT_ROOT).stdout
        print(so)
        print("Eclipsa doesn't allow me to see if the exploit worked or not =(\nJust have to assume it did, if it didn't then reboot into DFU mode and re-run PyBoot")
        return
    elif "CPID:8003" in serial_number:
        so = TOOLS.eclipsa8003.execute(cwd=PROJECT_ROOT).stdout
        print(so)
        print("Eclipsa doesn't allow me to see if the exploit worked or not =(\nJust have to assume it did, if it didn't then reboot into DFU mode and re-run PyBoot")
        return
    elif "CPID:7000" in serial_number:
        so = TOOLS.eclipsa7000.execute(cwd=PROJECT_ROOT).stdout
        print(so)
        print("Eclipsa doesn't allow me to see if the exploit worked or not =(\nJust have to assume it did, if it didn't then reboot into DFU mode and re-run PyBoot")
        return
    elif "CPID:7001" in serial_number:
        so = TOOLS.eclipsa8000.execute(cwd=PROJECT_ROOT).stdout
        print(so)
        print("Eclipsa doesn't allow me to see if the exploit worked or not =(\nJust have to assume it did, if it didn't then reboot into DFU mode and re-run PyBoot")
        return
    else:
        print("Please open an issue and let me know what device you are using/it's CPID and I will add support ASAP")
        exit(2)
