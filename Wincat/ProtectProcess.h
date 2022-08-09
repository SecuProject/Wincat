#pragma once


#ifndef PROTECT_PROCESS_HEADER_H
#define PROTECT_PROCESS_HEADER_H

BOOL SetHook(VOID);
BOOL ProtectProcess(Kernel32_API kernel32, ntdll_API ntdllApi);
BOOL EnableACG(VOID);


BOOL CheckForDebugger(VOID);
BOOL IsDebuggerPresentPEB(VOID);

BOOL CheckCodeSection(VOID);

#endif