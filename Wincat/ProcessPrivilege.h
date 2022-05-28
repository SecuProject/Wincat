#pragma once


#ifndef PROCESS_PRIVILEGE_HEADER_H
#define PROCESS_PRIVILEGE_HEADER_H

BOOL CheckUserPrivilege(HANDLE hToken);
BOOL IsTokenService(HANDLE hToken);

#endif