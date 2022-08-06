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
    STATUS_OK2,
    STATUS_ERROR,
    STATUS_ERROR2,
    STATUS_WARNING,
    STATUS_WARNING2,
    STATUS_TITLE,
    STATUS_TITLE2,
    STATUS_NONE,
    STATUS_DEBUG,
    STATUS_INFO,
    STATUS_INFO2,
}MSG_STATUS;

extern MSG_LEVEL msgLevelGlobal;

void printMsg(MSG_STATUS msgStatus, MSG_LEVEL msgLevel, const char* format, ...);

DWORD DisplayError(LPWSTR pszAPI);

#endif