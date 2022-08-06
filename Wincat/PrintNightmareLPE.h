#pragma once

#ifndef PRINT_NIGHTMARE_LPE_HEADER_H
#define PRINT_NIGHTMARE_LPE_HEADER_H


BOOL ExploitPrintNightmareLPE(Advapi32_API advapi32, char* PathExeToRun, WCHAR* UipAddress, char* port, char* wincatDefaultDir);

#endif