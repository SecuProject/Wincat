#pragma once


#ifndef EASY_PRI_ESC_HEADER_H
#define EASY_PRI_ESC_HEADER_H

typedef struct {
	BOOL IsAlwaysInstallElevated;
	BOOL IsCdpSvcLPE;
	BOOL IsUserPrivilege;
	BOOL IsTokenService;
}EasyPriEsc;

EasyPriEsc EasyPrivEsc(Kernel32_API kernal32, Advapi32_API advapi32);

#endif