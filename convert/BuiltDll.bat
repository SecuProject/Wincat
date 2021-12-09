@echo off

set tmpDir=%temp%\BuildDir
set CabCompression=..\convert\Others\CabCompression.exe
set FileToHex=..\convert\Others\FileToHex.exe

echo.
echo ============================================================
echo ================= Building UacBypassDll.dll ================
echo ============================================================
echo.
mkdir %tmpDir%
copy ..\x64\Release\UacBypassDll.dll %tmpDir%\UacBypassDll.dll
%CabCompression% %tmpDir%\UacBypassDll.dll %tmpDir%\UacBypassDll.dll.cab
%FileToHex% -i %tmpDir%\UacBypassDll.dll.cab -o ..\Wincat\UacBypassDll.h -n UAC_BYPASS_DLL /y

rem Cleanup
del /f /q %tmpDir%
rmdir %tmpDir%
echo [+] Done !
echo.