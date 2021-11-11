@echo off
echo.
echo          =========================================
echo          =        Precompilation Start !         =
echo          =========================================
echo.

IF NOT EXIST comp (
    mkdir comp
)

IF "%1"=="x64" (
    echo [*] Stating powershell script x64
    powershell.exe -exec bypass ./Others/convertx64.ps1
)ELSE IF "%1"=="x86" (
    echo [*] Stating powershell script x86
    powershell.exe -exec bypass ./Others/convertx86.ps1
)
echo [*] Cleaning up 
rmdir comp /s /q


:END
echo.
echo          =========================================
echo          =         Precompilation done !         =
echo          =========================================
echo.
exit 0