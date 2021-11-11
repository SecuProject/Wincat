#pragma once

#ifndef MESSAGE_HEADER_H
#define MESSAGE_HEADER_H

typedef enum {
    LEVEL_VERBOSE = 100,
    LEVEL_DEFAULT = 50,
    LEVEL_LOW = 10,
}MSG_LEVEL;


typedef enum {
    STATUS_OK,
    STATUS_ERROR,
    STATUS_ERROR2,
    STATUS_WARNING,
    STATUS_TITLE,
    STATUS_NONE,
    STATUS_DEBUG,
    STATUS_INFO,
}MSG_STATUS;

extern MSG_LEVEL msgLevelGlobal;

void printMsg(MSG_STATUS msgStatus, MSG_LEVEL msgLevel, const char* format, ...);

DWORD DisplayError(LPWSTR pszAPI);

#endif