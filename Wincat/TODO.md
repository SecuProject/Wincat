
PE:
- Mimikzat ??? 

Obf:
- [ ] Load function dynamically 
- [ ] Uac bypass 4: compress dropped dll !!!
- [ ] AntiDump


## Powershell:

- Start Powershell:
  - `Import-Module .\PowerUp.ps1`
  - `Import-Module .\Sherlock.ps1`
  - `Import-Module .\PrivescCheck.ps1`
## toHex 
  - check header EXE
  - check header 0x0A,0x51,0xE5,0xC0,0x18,0x00

## Others

- [ ] ADD msf injection
    - [ ] enable process injection (-pi)
    - [ ] in arg set target process: (-pt PROCESS_NAME) [Default smartscreen.exe] 
- [ ] persistence 
- [ ] Copy to C:\Windows\Tasks
    - [ ] set as arg 
## Others Tools:
- [ ] LSASS dump
	- Load api
- [ ] HiveNightmare
- [ ] Update netscan