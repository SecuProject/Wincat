#pragma once


#ifndef MSF_REVERSE_HTTP_HEADER_H
#define MSF_REVERSE_HTTP_HEADER_H

BOOL StagerReverseHTTP(Kernel32_API kernel32, Wininet_API wininet, WCHAR* ServeurIP, int Port);
BOOL StagerReverseHTTPS(Kernel32_API kernel32, Wininet_API wininet, WCHAR* ServeurIP, int Port);

#endif