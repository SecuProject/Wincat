#pragma once


#ifndef PROTECT_PROCESS_HEADER_H
#define PROTECT_PROCESS_HEADER_H

BOOL ProtectProcess(Kernel32_API kernel32, ntdll_API ntdllApi);
BOOL EnableACG(VOID);


BOOL CheckForDebugger(VOID);
BOOL IsDebuggerPresentPEB(VOID);

BOOL CheckCodeSection(Kernel32_API Kernel32Api);

#endif