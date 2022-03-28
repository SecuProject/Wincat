#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "Message.h"
#include "Tools.h"
#include "GetDefaultPath.h"


#define TEST_FILE_PATH_LENGTH       
#define TEST_FILE_NAME_LENGTH       30
#define TEST_FILE_NAME_SORT_LENGTH  20
#define TEST_FILE_VALUE_LENGTH      40
#define FILE_EXTENSION_LENGTH       4

BOOL WriteTestFile(char* fileName, char* testValue) {
    HANDLE hFile;
    hFile = CreateFileA(fileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!WriteFile(hFile, testValue, (DWORD)strlen(testValue), NULL, NULL)) {
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    return TRUE;
}
BOOL ReadTestFile(char* fileName, char* testValue) {
    char fileBuffer[TEST_FILE_VALUE_LENGTH + 1];
    HANDLE hFile;
    DWORD dwBytesRead = 0;

    hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!ReadFile(hFile, fileBuffer, TEST_FILE_VALUE_LENGTH, &dwBytesRead, NULL)) {
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    if (dwBytesRead > 0 && dwBytesRead < TEST_FILE_VALUE_LENGTH)
        fileBuffer[dwBytesRead] = '\0';
    else
        fileBuffer[TEST_FILE_VALUE_LENGTH] = '\0';
    return strcmp(fileBuffer, testValue) == 0;
}

BOOL SetVariable(const char* pathDirecotry, char** ppTestFileValue, char** ppTestFilePath) {
    char* testFilePath;
    char* testFileValue;
    char* testFileName;
    UINT testFilePathSize;

    testFileValue = (char*)malloc(TEST_FILE_VALUE_LENGTH + 1);
    if (testFileValue == NULL) {
        return FALSE;
    }

    srand((UINT)time(0));
    GenRandDriverName(testFileValue, TEST_FILE_VALUE_LENGTH);



    testFilePathSize = (UINT)strlen(pathDirecotry) + TEST_FILE_NAME_SORT_LENGTH + 1 + FILE_EXTENSION_LENGTH + 1;
    testFilePath = (char*)malloc(testFilePathSize);
    if (testFilePath == NULL) {
        free(testFileValue);
        return FALSE;
    }

    testFileName = (char*)malloc(TEST_FILE_NAME_LENGTH + 1);
    if (testFileName == NULL) {
        free(testFilePath);
        free(testFileValue);
        return FALSE;
    }

    GenRandDriverName(testFileName, TEST_FILE_NAME_SORT_LENGTH);
    strcat_s(testFileName, TEST_FILE_NAME_LENGTH + 1, ".txt");
    sprintf_s(testFilePath, testFilePathSize, "%s\\%s", pathDirecotry, testFileName);
    free(testFileName);

    *ppTestFileValue = testFileValue;
    *ppTestFilePath = testFilePath;
    return TRUE;
}

BOOL TestPathValide(const char* pathDirecotry) {
    char* testFileValue;
    char* testFilePath;

    if (!SetVariable(pathDirecotry, &testFileValue, &testFilePath)) {
        return FALSE;
    }
    // Check if the directory exists
    if (!CreateDirectoryA(pathDirecotry, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return FALSE;
    }

    if (!WriteTestFile(testFilePath, testFileValue)) {
        printMsg(STATUS_ERROR, LEVEL_VERBOSE, "Fail to write file '%s'", testFilePath);
        DeleteFileA(testFilePath);
        free(testFileValue);
        free(testFilePath);
        return FALSE;
    }
    if (!ReadTestFile(testFilePath, testFileValue)) {
        printMsg(STATUS_ERROR, LEVEL_VERBOSE, "Fail to read file '%s'", testFilePath);
        DeleteFileA(testFilePath);
        free(testFileValue);
        free(testFilePath);
        return FALSE;
    }
    DeleteFileA(testFilePath);
    free(testFileValue);
    free(testFilePath);
    return TRUE;
}

BOOL GetDefaultPath(char** ppathDirecotry, char** ppwincatDefaultPath) {
    const char* pathToTest[] = {
        "C:\\Windows\\Tasks",
        "C:\\Windows\\System32\\Tasks",
        "C:\\Windows\\Temp\\WinTools",
        "C:\\programdata\\WinTools",
        "C:\\Users\\Public\\Documents\\WinTools"
    };
    const char programName[] = "wincat.exe";
    BOOL isPathValide = FALSE;
    int i;

    for (i = 0; i < sizeof(pathToTest) / sizeof(char*) && !isPathValide; i++)
        isPathValide = TestPathValide(pathToTest[i]);

    if (i < sizeof(pathToTest) / sizeof(char*) && isPathValide) {
        i--;
        UINT pathDirecotrySize = (UINT)strlen(pathToTest[i]) + 1;
        
        char* pathDirecotry = (char*)malloc(pathDirecotrySize);
        if (pathDirecotry == NULL)
            return FALSE;
        strcpy_s(pathDirecotry, pathDirecotrySize, pathToTest[i]);
        

        UINT wincatDefaultPathSize = (UINT)strlen(pathToTest[i]) + sizeof(programName) + 1 + 1;
        char* wincatDefaultPath = (char*)malloc(wincatDefaultPathSize);
        if (wincatDefaultPath == NULL) {
            free(pathDirecotry);
            return FALSE;
        }
        sprintf_s(wincatDefaultPath, wincatDefaultPathSize, "%s\\%s", pathDirecotry, programName);
        *ppwincatDefaultPath = wincatDefaultPath;
        *ppathDirecotry = pathDirecotry;
        return TRUE;
    }
    return FALSE;
}

/*
int main() {
    char* pathDirecotry;
    if (GetDefaultPath(&pathDirecotry))
        printMsg(STATUS_INFO, LEVEL_DEFAULT, "Target path : '%s'\n", pathDirecotry);
    else
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "No target path was found");
    system("pause");
    return FALSE;
}*/