@echo off
mkdir header
bin\FileToHex.exe -i DuplicateToke.exe -o header/DuplicateToke.h -n DuplicateTokeFile
bin\FileToHex.exe -i lsass.exe -o header/lsass.h -n lsass
bin\FileToHex.exe -i runAsAdmin.exe -o header/runAsAdmin.h -n runAsAdmin
pause