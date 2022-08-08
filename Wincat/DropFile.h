#pragma once

#ifndef DROP_FILE_HEADER_H
#define DROP_FILE_HEADER_H

#include "MgArguments.h"

#include "LoadAPI.h"

typedef struct StrucFile {
    const WCHAR* filename;
    const char* buffer;
    const int size;
    BOOL isExe;
    BOOL isSafe;
}StrucFile;

BOOL DropFiles(Kernel32_API kernel32, Cabinet_API cabinetAPI, char* wincatDefaultDir, ToDropEnum toDROP);
BOOL DropFile(Kernel32_API kernel32, Cabinet_API cabinetAPI, char* wincatDefaultDir, StrucFile fileStruc);


#endif