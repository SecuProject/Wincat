#include <windows.h>
#include <stdio.h>
#include <time.h>


//////////////////////////// #include "Tools.h" ////////////////////////////
//
void gen_random(char* string, const int len) {
    char alphanum[63];
    int ich = 0;
    for (char l = 'a'; l <= 'z'; ++l, ich++)
        alphanum[ich] = l;
    for (char l = 'A'; l <= 'Z'; ++l, ich++)
        alphanum[ich] = l;
    for (char l = '0'; l <= '9'; ++l, ich++)
        alphanum[ich] = l;


    for (int i = 0; i < len; ++i)
        string[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    string[len] = 0;
}
//
//////////////////////////// #include "Tools.h" ////////////////////////////




//////////////////////////// #include "message.h" ////////////////////////////
// 




typedef enum {
    LEVEL_VERBOSE = 100,
    LEVEL_DEFAULT = 50,
    LEVEL_LOW     = 10,
}MSG_LEVEL;


typedef enum {
    STATUS_OK,
    STATUS_ERROR,
    STATUS_WARNING,
    STATUS_TITLE,
    STATUS_NONE,
    STATUS_DEBUG,
    STATUS_INFO,
}MSG_STATUS;

MSG_LEVEL msgLevelGlobal = LEVEL_DEFAULT;


void printMsg(MSG_STATUS msgStatus, MSG_LEVEL msgLevel,const char* format, ...) {
    if (msgLevel <= msgLevelGlobal) {
        switch (msgStatus) {
        case STATUS_OK:
            printf("[+] ");
            break;
        case STATUS_ERROR:
            printf("[x] ");
            break;
        case STATUS_WARNING:
            printf("[w] ");
            break;
        case STATUS_TITLE:
            printf("[-] ");
            break;
        case STATUS_DEBUG:
            printf("[D] ");
            break;
        case STATUS_INFO:
            printf("[i] ");
            break;
        case STATUS_NONE:
        default:
            break;
        }
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}
//
//////////////////////////// #include "message.h" ////////////////////////////


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
    if (!WriteFile(hFile, testValue, strlen(testValue), NULL, NULL)) {
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    return TRUE;
}
BOOL ReadTestFile(char* fileName, char* testValue) {
    char fileBuffer[TEST_FILE_VALUE_LENGTH +1];
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
    int testFilePathSize;

    testFileValue = (char*)malloc(TEST_FILE_VALUE_LENGTH + 1);
    if (testFileValue == NULL) {
        return FALSE;
    }

    srand((UINT)time(0));
    gen_random(testFileValue, TEST_FILE_VALUE_LENGTH);



    testFilePathSize = strlen(pathDirecotry) + TEST_FILE_NAME_SORT_LENGTH + 1 + FILE_EXTENSION_LENGTH +1;
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

    gen_random(testFileName, TEST_FILE_NAME_SORT_LENGTH);
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
        printMsg(STATUS_ERROR, LEVEL_VERBOSE,"Fail to write file '%s'.\n", testFilePath);
        DeleteFileA(testFilePath);
        free(testFileValue);
        free(testFilePath);
        return FALSE;
    }
    if (!ReadTestFile(testFilePath, testFileValue)) {
        printMsg(STATUS_ERROR, LEVEL_VERBOSE, "Fail to read file '%s'.\n", testFilePath);
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

BOOL GetTargetDirectory(char** pathDirecotry){
    const char* pathToTest[] = {
        "C:\\Windows\\System32",
        "C:\\Windows\\Tasks",
        "C:\\Windows\\Temp\\WinTools",
        "C:\\programdata\\WinTools"
    };
    BOOL isPathValide = FALSE;
    int i;

    for (i = 0; i < sizeof(pathToTest) / sizeof(char*) && !isPathValide; i++)
        isPathValide = TestPathValide(pathToTest[i]);

    if (i < sizeof(pathToTest) / sizeof(char*) && isPathValide) {
        i--;
        *pathDirecotry = (char*)pathToTest[i];
        return TRUE;
    }
    return FALSE;
}


int main() {
    char* pathDirecotry;
    if(GetTargetDirectory(&pathDirecotry))
        printMsg(STATUS_INFO, LEVEL_DEFAULT, "Target path : '%s'\n", pathDirecotry);
    else
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "No target path was found !\n");
    system("pause");
    return FALSE;
}