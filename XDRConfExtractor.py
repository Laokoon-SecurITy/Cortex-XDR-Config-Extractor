#!/usr/bin/env python3
import sys
import re

from termcolor import colored


def help():
    print_banner()
    print(colored("LEGAL DISCLAIMER", "red", attrs=["bold"]))
    print(
        colored(
            "Usage of CortexXDRConfigExtractor for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes. This tool is meant to be used in Red Team Assessments and to audit the XDR Settings. Do not use this tool in any harmful way.\n",
            "red",
            attrs=["bold"],
        )
    )
    print(
        "With this tool its possible to parses the Database Lock Files of the Cortex XDR Agent by Palo Alto Networks and extracts Agent Settings, the Hash and Salt of the Uninstall Password, as well as possible Exclusions.\n"
    )
    print(
        "The technique to extract Agent Settings from the Database Locks was initialy released by mr.d0x https://mrd0x.com/cortex-xdr-analysis-and-bypass/  "
    )
    print("\n")
    print("There are multiple ways to get hold of the DB lock files:")
    print(
        colored(
            "################\tAgent Version <7.8\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(
        "Up to Agent Version 7.8 any authenticated User can generate a Support File on Windows via Cortex XDR Console in the System Tray."
    )
    print("The databse lock files can be found within the zip:")
    print(
        colored(
            "logs_[ID].zip\\Persistence\\agent_settings.db\\", "red", attrs=["bold"]
        )
    )
    print("\n")
    print(
        colored(
            "################\tAgent Version >7.8\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(
        "Support Files files from Agents running Version 7.8 or higher are encrypted, but if you have elevated privileges on the Windows Maschine the files can be directly copied from the following directory, without encryption."
    )
    print(
        colored(
            "C:\\ProgramData\\Cyvera\\LocalSystem\\Persistence\\agent_settings.db\\\n",
            "red",
            attrs=["bold"],
        )
    )
    print(
        "Generated Support Files are not deleted regulary, so it might be possible to find old, unencrypted Support Files in the following folders:"
    )
    print(
        colored(
            "C:\\Users\\[Username]\\AppData\\Roaming\\PaloAltoNetworks\\Traps\\support\\",
            "red",
            attrs=["bold"],
        )
    )

    sys.exit()


def print_banner():

    banner = """
   ____           _            __  ______  ____                              
  / ___|___  _ __| |_ _____  __\ \/ /  _ \|  _ \                             
 | |   / _ \| '__| __/ _ \ \/ / \  /| | | | |_) |                            
 | |__| (_) | |  | ||  __/>  <  /  \| |_| |  _ <                             
  \____\___/|_|   \__\___/_/\_\/_/\_\____/|_| \_\              _             
  / ___|___  _ __  / _(_) __ _  | ____|_  _| |_ _ __ __ _  ___| |_ ___  _ __ 
 | |   / _ \| '_ \| |_| |/ _` | |  _| \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
 | |__| (_) | | | |  _| | (_| | | |___ >  <| |_| | | (_| | (__| || (_) | |   
  \____\___/|_| |_|_| |_|\__, | |_____/_/\_\\\\__|_|  \__,_|\___|\__\___/|_|   
                         |___/                                                
                         
    █░░ ▄▀█ █▀█ █▄▀ █▀█ █▀█ █▄░█   █▀ █▀▀ █▀▀ █░█ █▀█ █ ▀█▀ █▄█ 
    █▄▄ █▀█ █▄█ █░█ █▄█ █▄█ █░▀█   ▄█ ██▄ █▄▄ █▄█ █▀▄ █ ░█░ ░█░   
    [===]       Homepage: https://laokoon-security.com      [===]
    [===]       Follow us on Twitter: @LaokoonSecurITy      [===]
    [===]           Created by: Luca Greeb (Yeeb)           [===]                                                                     
	"""

    print(colored(banner, "green", attrs=["bold"]))


def openfile(name):

    fd = open(name, "rb")
    data = fd.read().decode("utf-8", "ignore")
    fd.close()

    findstrings(data)


def findstrings(thedata):
    count = 0  # This keeps track of consecutive printable characters
    charslist = []  # Place to keep characters
    printable = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz/\.,1234567890!@#$%^&*(){}[] =:"_'  # Characters to search for
    allstrings = ""  # Place to keep the strings
    for character in thedata:
        if character in printable:
            charslist.append(character)
            count += 1
        else:
            if count >= 4:
                allstrings = allstrings + ("".join(charslist[-count:]))

                count = 0

    regex(allstrings)


def regex(strings):
    # Regex Patterns
    regex_salt = '"salt":".+?"'
    regex_password = '"password":".+?"'
    regex_signers = '"whitelistSigners":\[".+?\]'
    regex_filetype_dll = '"FileTypeDll":\{".+?\]'
    regex_filetype_pe = '"FileTypeExecutable":\{".+?\].+?\]'
    regex_filetype_macros = '"FileTypeOfficeDocs":\{".+?\].+?\]'
    regex_filetype_passwordstealing = '"passwordStealing",".+?.+?\]'
    regex_filetype_webshell = '"webshellDroppers",".+?.+?\]'
    regex_filetype_childprocess = '"legitimateProcesses",".+?.+?\]'
    regex_filetype_BIOC = '"dynamicSecurityEngine",".+?.+?\]'
    regex_filetype_scan = '"scanEndpoints",".+?.+?\}}'
    regex_passwordtheft = (
        '{"mode":"(enabled|disabled)","type":"passwordTheftProtection"'
    )
    regex_global_hash_BIOC = '"hash_sha256":".+?"},"settings":{"action":".+?}'
    regex_ransomware_status = '{"mode":"(report|block|disabled)","type":"ransomware"'
    regex_ransomware_settings = '"type":"ransomware".+?}}'

    # Regex Search
    agent_salt = re.findall(regex_salt, strings)
    agent_password = re.findall(regex_password, strings)
    agent_signers = re.findall(regex_signers, strings)
    agent_exclusion_dll = re.findall(regex_filetype_dll, strings)
    agent_exclusion_pe = re.findall(regex_filetype_pe, strings)
    agent_exclusion_macros = re.findall(regex_filetype_macros, strings)
    agent_exclusion_passwordstealing = re.findall(
        regex_filetype_passwordstealing, strings
    )
    agent_exclusion_webshell = re.findall(regex_filetype_webshell, strings)
    agent_exclusion_childprocess = re.findall(regex_filetype_childprocess, strings)
    agent_exclusion_BIOC = re.findall(regex_filetype_BIOC, strings)
    agent_exclusion_scan = re.findall(regex_filetype_scan, strings)
    agent_exclusion_passwordtheft = re.findall(regex_passwordtheft, strings)
    agent_exclusion_global_hash_BIOC = re.findall(regex_global_hash_BIOC, strings)
    agent_ransomware_status = re.findall(regex_ransomware_status, strings)
    agent_ransomware_settings = re.findall(regex_ransomware_settings, strings)

    # Remove Doublicates and Convert to String
    agent_salt = str(set(agent_salt))
    agent_password = str(set(agent_password))
    agent_signers = str(set(agent_signers))
    agent_exclusion_dll = str(set(agent_exclusion_dll))
    agent_exclusion_pe = str(set(agent_exclusion_pe))
    agent_exclusion_macros = str(set(agent_exclusion_macros))
    agent_exclusion_passwordstealing = str(set(agent_exclusion_passwordstealing))
    agent_exclusion_webshell = str(set(agent_exclusion_webshell))
    agent_exclusion_childprocess = str(set(agent_exclusion_childprocess))
    agent_exclusion_BIOC = str(set(agent_exclusion_BIOC))
    agent_exclusion_scan = str(set(agent_exclusion_scan))
    agent_exclusion_passwordtheft = str(set(agent_exclusion_passwordtheft))
    agent_exclusion_global_hash_BIOC = str(set(agent_exclusion_global_hash_BIOC))
    agent_ransomware_settings = str(set(agent_ransomware_settings))
    agent_ransomware_status = str(set(agent_ransomware_status))

    # (Horrible) Cleanup
    agent_salt = re.sub('\W+salt":"', "", agent_salt)
    agent_salt = re.sub("\W+", "", agent_salt)
    agent_password = re.sub('\W+password":"', "", agent_password)
    agent_password = re.sub("\W+", "", agent_password)
    agent_signers = [m.split(", ") for m in re.findall(r'"(.*?)"', agent_signers)]
    agent_signers = (
        str(agent_signers)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace('"', "")
        .replace("whitelistSigners", "")
        .replace("\n, ", "\n ")
    )
    agent_exclusion_dll_path = re.findall(
        '"PathWhiteList":\[".+?"\]', agent_exclusion_dll
    )
    agent_exclusion_dll_path = [
        m.split(", ")
        for m in re.findall(r'"(.*?)"', str(set(agent_exclusion_dll_path)))
    ]
    agent_exclusion_dll_path = (
        str(agent_exclusion_dll_path)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace('"', "")
        .replace("PathWhiteList", "")
        .replace("\n, ", "\n ")
        .replace("\\\\\\\\\\\\\\\\", "\\")
    )
    agent_exclusion_dll_settings = re.findall(
        '"FileTypeDll":.+?,"Path', agent_exclusion_dll
    )
    agent_exclusion_dll_settings = (
        str(agent_exclusion_dll_settings)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace(',"Path', "")
        .replace(",", "\n ")
        .replace('"FileTypeDll":{', " ")
    )
    agent_exclusion_pe_path = re.findall(
        '"PathWhiteList":\[".+?"\]', agent_exclusion_pe
    )
    agent_exclusion_pe_path = [
        m.split(", ") for m in re.findall(r'"(.*?)"', str(set(agent_exclusion_pe_path)))
    ]
    agent_exclusion_pe_path = (
        str(agent_exclusion_pe_path)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace('"', "")
        .replace("PathWhiteList", "")
        .replace("\n, ", "\n ")
        .replace("\\\\\\\\\\\\\\\\", "\\")
    )
    agent_exclusion_pe_settings = re.findall(
        '"FileTypeExecutable":.+?,"Path', agent_exclusion_pe
    )
    agent_exclusion_pe_settings = (
        str(agent_exclusion_pe_settings)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace(',"Path', "")
        .replace(",", "\n ")
        .replace('"FileTypeExecutable":{', " ")
    )
    agent_exclusion_macros_path = re.findall(
        '"PathWhiteList":\[".+?"\]', agent_exclusion_macros
    )
    agent_exclusion_macros_path = [
        m.split(", ")
        for m in re.findall(r'"(.*?)"', str(set(agent_exclusion_macros_path)))
    ]
    agent_exclusion_macros_path = (
        str(agent_exclusion_macros_path)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace('"', "")
        .replace("PathWhiteList", "")
        .replace("\n, ", "\n ")
        .replace("\\\\\\\\\\\\\\\\", "\\")
    )
    agent_exclusion_macros_settings = re.findall(
        '"FileTypeOfficeDocs":.+?,"Path', agent_exclusion_macros
    )
    agent_exclusion_macros_settings = (
        str(agent_exclusion_macros_settings)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace(',"Path', "")
        .replace(",", "\n ")
        .replace('"FileTypeOfficeDocs":{"', " ")
    )
    agent_exclusion_passwordstealing_path = re.findall(
        '"whitelistFolders":\[".+?"\]', agent_exclusion_passwordstealing
    )
    agent_exclusion_passwordstealing_path = [
        m.split(", ")
        for m in re.findall(r'"(.*?)"', str(set(agent_exclusion_passwordstealing_path)))
    ]
    agent_exclusion_passwordstealing_path = (
        str(agent_exclusion_passwordstealing_path)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace('"', "")
        .replace("whitelistFolders", "")
        .replace("\n, ", "\n ")
        .replace("\\\\\\\\\\\\\\\\", "\\")
    )
    agent_exclusion_webshell_path = re.findall(
        '"whitelistFolders":\[".+?"\]', agent_exclusion_webshell
    )
    agent_exclusion_webshell_path = [
        m.split(", ")
        for m in re.findall(r'"(.*?)"', str(set(agent_exclusion_webshell_path)))
    ]
    agent_exclusion_webshell_path = (
        str(agent_exclusion_webshell_path)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace('"', "")
        .replace("whitelistFolders", "")
        .replace("\n, ", "\n ")
        .replace("\\\\\\\\\\\\\\\\", "\\")
    )
    agent_exclusion_childprocess_childs = re.findall(
        '{"parentProcess":.+?}', agent_exclusion_childprocess
    )
    agent_exclusion_childprocess_childs = (
        str(agent_exclusion_childprocess_childs)
        .replace("[", "")
        .replace("]", "")
        .replace("'", "")
        .replace('"', "")
        .replace("whitelistFolders", " ")
        .replace("\n, ", "\n ")
        .replace(", {", "\n {")
    )
    agent_exclusion_BIOC_path = re.findall(
        '"whitelistFolders":\[".+?"\]', agent_exclusion_BIOC
    )
    agent_exclusion_BIOC_path = [
        m.split(", ")
        for m in re.findall(r'"(.*?)"', str(set(agent_exclusion_BIOC_path)))
    ]
    agent_exclusion_BIOC_path = (
        str(agent_exclusion_BIOC_path)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace('"', "")
        .replace("whitelistFolders", "")
        .replace("\n, ", "\n ")
        .replace("\\\\\\\\\\\\\\\\", "\\")
    )
    agent_exclusion_scan_path = re.findall(
        '"whitelistFolders":\[".+?"\]', agent_exclusion_scan
    )
    agent_exclusion_scan_path = [
        m.split(", ")
        for m in re.findall(r'"(.*?)"', str(set(agent_exclusion_scan_path)))
    ]
    agent_exclusion_scan_path = (
        str(agent_exclusion_scan_path)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace('"', "")
        .replace("whitelistFolders", "")
        .replace("\n, ", "\n ")
        .replace("\\\\\\\\\\\\\\\\", "\\")
    )
    agent_exclusion_passwordtheft_status = re.sub(
        "\W+", "", agent_exclusion_passwordtheft
    )
    agent_exclusion_passwordtheft_status = (
        str(agent_exclusion_passwordtheft_status)
        .replace("{", " ")
        .replace("}", "\n")
        .replace("'", "")
        .replace(',"Path', "")
        .replace(",", "\n")
    )
    agent_exclusion_global_hash_BIOC = re.findall(
        "[A-Fa-f0-9]{64}", agent_exclusion_global_hash_BIOC
    )
    agent_exclusion_global_hash_BIOC = (
        str(agent_exclusion_global_hash_BIOC)
        .replace("[", " ")
        .replace("]", "\n")
        .replace("'", "")
        .replace(',"Path', "")
        .replace(",", "\n")
    )
    agent_ransomware_status = (
        str(agent_ransomware_status)
        .replace("{", " ")
        .replace("}", "\n")
        .replace("'", "")
        .replace(',"Path', "")
        .replace(",", "\n")
    )
    agent_ransomware_settings = (
        str(agent_ransomware_settings)
        .replace("[", "")
        .replace("]", "\n")
        .replace("'", "")
        .replace(',"Path', "")
        .replace(",", "\n ")
        .replace("}}}", "}")
    )

    # Output
    print(
        colored(
            "################\tAGENT HASH AND SALT\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print(
        "The password has at least 9 or more characters and must contain letters, numbers, or any of the following symbols: !()-._`~@#\"'"
    )
    print(
        "For more information see: "
        + colored(
            "https://mrd0x.com/cortex-xdr-analysis-and-bypass/\n",
            "blue",
            attrs=["bold"],
        )
    )
    print(colored("AGENT SALT:\t" + agent_salt, "red", attrs=["bold"]))
    print(colored("AGENT HASH:\t" + agent_password, "red", attrs=["bold"]))
    print("\n")

    print(
        colored(
            "################\tEXCLUDED SIGNERS\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print(
        "Software signed with these Names will not blocked by XDR in the first place.\n"
    )
    print(colored("SIGNERS NAMES:\n" + agent_signers, "red", attrs=["bold"]))

    print(
        colored(
            "################\tDLL SECURITY\t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print("DLLs from these Paths will not be blocked by Cortex XDR\n")
    print(
        colored(
            "EXCLUDED PATH OR FILES:\n" + agent_exclusion_dll_path,
            "red",
            attrs=["bold"],
        )
    )
    print(
        colored(
            "DLL MODULE SETTINGS:\n" + agent_exclusion_dll_settings,
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tPE SECURITY\t\t##############\n", "green", attrs=["bold"]
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print("PEs in these Paths will not be blocked by Cortex XDR\n")
    print(
        colored(
            "EXCLUDED PATH OR FILES:\n" + agent_exclusion_pe_path, "red", attrs=["bold"]
        )
    )
    print(
        colored(
            "PE MODULE SETTINGS:\n" + agent_exclusion_pe_settings, "red", attrs=["bold"]
        )
    )

    print(
        colored(
            "################\tMACRO SECURITY\t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print("This module will prevent malicious macro files from running.\n")
    print(
        colored(
            "EXCLUDED PATH OR FILES:\n" + agent_exclusion_macros_path,
            "red",
            attrs=["bold"],
        )
    )
    print(
        colored(
            "MACRO MODULE SETTINGS:\n" + agent_exclusion_macros_settings,
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tCREDENTIAL GATHERING\t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print(
        "This module protects from processes trying to access/steal passwords and other sensitive credentials.\n"
    )
    print(
        colored(
            "EXCLUDED PATH OR FILES:\n" + agent_exclusion_passwordstealing_path,
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tWEBSHELL PROTECTION\t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print("This module is the protection of processes dropping webshells\n")
    print(
        colored(
            "EXCLUDED PATH OR FILES:\n" + agent_exclusion_webshell_path,
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tCHILDPROCESS EXCLUSIONS\t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print(
        "This module prevents script-based attacks by blocking known targeted processes from launching malicous child processes.\n"
    )
    print(
        colored(
            "EXCLUDED PROCESS CHAINS:\n"
            + str(agent_exclusion_childprocess_childs)
            + "\n",
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tBEHAVIORIAL EXCLUSIONS\t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print(
        "This module prevents attacks that leverage LOLBAS by monitoring endpoint activity for malicious causality chains.\n"
    )
    print(
        colored(
            "BEHAVIORIAL THREAT EXCLUSIONS:\n" + str(agent_exclusion_BIOC_path),
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tLOCAL SCAN EXCLUSIONS\t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print("This module scans harddrives and external drives for malware.\n")
    print(
        colored(
            "LOCAL SCAN EXCLUSIONS:\n" + str(agent_exclusion_scan_path),
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tMEMORY PROTECTION \t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print("This module tries to prevent memory access from programs like mimikatz. \n")
    print(
        colored(
            "MEMORY PROTECTION STATUS:\n"
            + str(agent_exclusion_passwordtheft_status + "\n"),
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tBEHAVIORAL HASH EXCEPTIONS \t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print("These hashes are globally excluded from behavioral alerts.  \n")
    print(
        colored(
            "EXCLUDED SHA256:\n" + str(agent_exclusion_global_hash_BIOC),
            "red",
            attrs=["bold"],
        )
    )

    print(
        colored(
            "################\tRANSOMWARE PROTECTION\t\t##############\n",
            "green",
            attrs=["bold"],
        )
    )
    print(colored("Description:\n", "green", attrs=["bold"]))
    print("The following settings are configured for the ransomware module.  \n")
    print(
        colored(
            "RANSOMWARE PROTECTION MODE:\n" + str(agent_ransomware_status),
            "red",
            attrs=["bold"],
        )
    )
    print(
        colored(
            "RANSOMWARE MODULE SETTINGS:\n" + agent_ransomware_settings,
            "red",
            attrs=["bold"],
        )
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage =\t"
            + sys.argv[0]
            + " [Filename].ldb\nHelp  =\t"
            + sys.argv[0]
            + " -h"
        )
        sys.exit()
        print("Test\n")
    if sys.argv[1] == "-h":
        help()
    filename = sys.argv[1]
    print_banner()
    openfile(filename)
