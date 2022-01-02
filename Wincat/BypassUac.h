#pragma once

#ifndef BYPASS_UAC_HEADER_H
#define BYPASS_UAC_HEADER_H


BOOL RunUacBypass(char* PathExeToRun, WCHAR* ipAddress, char* port, UAC_BYPASS_TEC UacBypassTec, char* wincatDefaultDir);
BOOL SaveRHostInfo(WCHAR* ipAddress, char* port);

#endif