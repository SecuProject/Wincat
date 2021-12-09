@echo off

set tmpDir=%temp%\BuildDir
set CabCompression=..\convert\Others\CabCompression.exe
set FileToHex=..\convert\Others\FileToHex.exe

echo.
echo  ============================================================
echo  ================= Building UacBypassDll.dll ================
echo  ============================================================
echo.


IF NOT EXIST %tmpDir% (
    mkdir %tmpDir%
)

IF "%1"=="x64" (
    copy ..\x64\Release\UacBypassDll.dll %tmpDir%\UacBypassDll.dll
    %CabCompression% %tmpDir%\UacBypassDll.dll %tmpDir%\UacBypassDll.dll.cab
    %FileToHex% -i %tmpDir%\UacBypassDll.dll.cab -o ..\Wincat\UacBypassDll64.h -n UAC_BYPASS_DLL_64 /y
)ELSE IF "%1"=="x86" (
    copy ..\Release\UacBypassDll.dll %tmpDir%\UacBypassDll.dll
    %CabCompression% %tmpDir%\UacBypassDll.dll %tmpDir%\UacBypassDll.dll.cab
    %FileToHex% -i %tmpDir%\UacBypassDll.dll.cab -o ..\Wincat\UacBypassDll32.h -n UAC_BYPASS_DLL_32 /y
)ELSE (
    echo Argument error!
)


rem Cleanup
del /f /q %tmpDir%
rmdir %tmpDir%
echo [+] Done !
echo.