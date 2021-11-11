@echo off
echo %cd%
set input=../x64/Debug
set output=FileToDrop

echo ========================================================
echo ==================== Convert Exe to Hex ================
echo ========================================================
echo > nul

rem del %output%/DuplicateToke.h
rem del %output%/lsass.h
rem del %output%/runAsAdmin.h


"../convert/FileToHex.exe" -i %input%/DuplicateToke.exe -o %output%/DuplicateToke.h -n DuplicateTokeFile
"../convert/FileToHex.exe" -i "%input%/dump lsass.exe" -o %output%/lsass.h -n lsass