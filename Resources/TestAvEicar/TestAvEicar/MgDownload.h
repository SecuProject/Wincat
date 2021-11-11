#pragma once

#ifndef MG_DOWNLOAD_HEADER_H
#define MG_DOWNLOAD_HEADER_H


BOOL InitMgDownload();
BOOL CleanMgDownload();

BOOL GetIp(const char* url, char* ipAddress);
BOOL MainMgDownload(const char* url, const char* urlPath, const char* filePath, DWORD* fileSize, BOOL isHTTPS);


BOOL IsFileExist(char* filePath);
BOOL TestReadFile(const char* filePath);

#endif