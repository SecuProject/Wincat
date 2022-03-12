@echo off
set wget=exeAll\wgetX64.exe -q


rem source Wget https://eternallybored.org/misc/wget/
rem https://github.com/jpillora/chisel/releases 
rem https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.exe?raw=true
rem https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk

echo [-] Stating to download tools
echo     [+] Downloading winPEAS 32
%wget% https://github.com/carlospolop/PEASS-ng/releases/download/20220310/winPEASx86_ofs.exe -O exeX86/winPEASx86.exe
echo     [+] Downloading winPEAS 64
%wget% https://github.com/carlospolop/PEASS-ng/releases/download/20220310/winPEASx64_ofs.exe -O exeX64/winPEASx64.exe
echo     [+] Downloading SharpHound
%wget% https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.exe?raw=true -O exeAll/SharpHound.exe
echo     [+] Downloading windows privesc check2
%wget% https://github.com/pentestmonkey/windows-privesc-check/blob/master/windows-privesc-check2.exe?raw=true -O exeAll/windowsPrivescCheck.exe

echo [-] Downloading powershell script
%wget% https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1 -O PowershellScript/Sherlock.ps1
%wget% https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 -O PowershellScript/PowerUp.ps1
%wget% https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 -O PowershellScript/PrivescCheck.ps1
%wget% https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1 -O PowershellScript/PrintNightmare.ps1




mkdir temp
cd temp 
echo     [+] Downloading ligolo-ng agent 32 bit
..\%wget% https://github.com/tnpitsecurity/ligolo-ng/releases/download/v0.2/ligolo-ng_agent_0.2_Windows_32bit.zip -O ligolo-ng_agent32.zip
tar -xf ligolo-ng_agent32.zip
move agent.exe ../exeX86/ligolo_ng_agent32.exe


echo     [+] Downloading ligolo-ng agent 64 bit
..\%wget% https://github.com/tnpitsecurity/ligolo-ng/releases/download/v0.2/ligolo-ng_agent_0.2_Windows_64bit.zip -O ligolo-ng_agent64.zip
tar -xf ligolo-ng_agent64.zip
move agent.exe ../exeX64/ligolo_ng_agent64.exe
cd ..
rmdir temp /s /q
echo [+] Done !
pause