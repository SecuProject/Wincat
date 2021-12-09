#pragma once

#ifndef DROP_FILE_HEADER_H
#define DROP_FILE_HEADER_H

#include "MgArguments.h"


typedef struct StrucFile {
    const WCHAR* filename;
    const char* buffer;
    const int size;
    BOOL isExe;
    BOOL isSafe;
}StrucFile;

BOOL DropFiles(char* wincatDefaultDir, ToDropEnum toDROP);
BOOL DropFile(char* wincatDefaultDir, StrucFile fileStruc);


#endif