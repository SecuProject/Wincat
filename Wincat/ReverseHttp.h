#pragma once


#ifndef MSF_REVERSE_HTTP_HEADER_H
#define MSF_REVERSE_HTTP_HEADER_H

BOOL StagerReverseHTTP(WCHAR* ServeurIP, int Port);
BOOL StagerReverseHTTPS(WCHAR* ServeurIP, int Port);

#endif