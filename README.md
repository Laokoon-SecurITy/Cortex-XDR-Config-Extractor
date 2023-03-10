# Cortex XDR Config Extractor

> :warning: For more information, please visit https://laokoon-security.com/cortex-xdr-config-exctractor/ (currently in German only)


This tool is meant to be used during Red Team Assessments and to audit the XDR Settings.

With this tool its possible to parse the ```Database Lock Files``` of the ```Cortex XDR Agent``` by Palo Alto Networks and extract ```Agent Settings```, the ```Hash and Salt``` of the ```Uninstall Password```, as well as possible ```Exclusions```.

<p align="center">
  <img  height="1000" src="https://raw.githubusercontent.com/Laokoon-SecurITy/Cortex-XDR-Config-Extractor/main/img/output.png">
</p>


## Supported Extractions
- Uninstall Password Hash & Salt
- Excluded Signer Names
- DLL Security Exclusions & Settings
- PE Security Exclusions & Settings
- Office Files Security Exclusions & Settings
- Credential Gathering Module Exclusions 
- Webshell Protection Module Exclusions 
- Childprocess Executionchain Exclusions 
- Behavorial Threat Module Exclusions 
- Local Malware Scan Module Exclusions 
- Memory Protection Module Status 
- Global Hash Exclusions 
- Ransomware Protection Module Modus & Settings
## Usage

```
Usage = ./XDRConfExtractor.py [Filename].ldb
Help  = ./XDRConfExtractor.py -h
```

## Getting Hold of Database Lock Files
### Agent Version <7.8
With Agent Versions prior to 7.8 any authenticated user can generate a Support File on Windows via Cortex XDR Console in the System Tray.
The databse lock files can be found within the zip:
```
logs_[ID].zip\Persistence\agent_settings.db\
```
<p align="center">
  <img  height="300" src="https://raw.githubusercontent.com/Laokoon-SecurITy/Cortex-XDR-Config-Extractor/main/img/console.png">
</p>


### Agent Version ≥7.8
Support files from Agents running Version 7.8 or higher are encrypted, but if you have elevated privileges on the Windows Maschine the files can be directly copied from the following directory, without encryption.

#### Method I
```
C:\ProgramData\Cyvera\LocalSystem\Persistence\agent_settings.db\
```
#### Method II
Generated Support Files are not deleted regulary, so it might be possible to find old, unencrypted Support Files in the following folder:
```
C:\Users\[Username]\AppData\Roaming\PaloAltoNetworks\Traps\support\
```
### Agent Version >8.1
Supposedly, since Agent version 8.1, it should no longer be possible to pull the data from the lock files. This has not been tested yet.

## Credits
This tool relies on a technique originally released by [mr.d0x](https://twitter.com/mrd0x) in April 2022 
https://mrd0x.com/cortex-xdr-analysis-and-bypass/

## Legal disclaimer
Usage of Cortex-XDR-Config-Extractor for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
