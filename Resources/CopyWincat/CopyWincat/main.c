#include <Windows.h>
#include <stdio.h>

BOOL CopyWinNC(const char* wincatDefaultPath) {
    BOOL retVal = FALSE;
    char* currentFilePath = (char*)calloc(MAX_PATH, 1);
    if (currentFilePath != NULL) {
        if (GetModuleFileNameA(NULL, currentFilePath, MAX_PATH) > 0) {
            if (CopyFileA(currentFilePath, wincatDefaultPath, FALSE)) {
                printf("Copy %s -> %s\n", currentFilePath, wincatDefaultPath);
                retVal = TRUE;
            }
                
        }
        free(currentFilePath);
    }
    return TRUE;
}

BOOL GetEnvVarAndCopyWincat(char** ppDefaultToolPath, char** ppWincatDefaultPath) {
    const char* defaultToolPath[] = {
        "C:\\Windows\\Tasks",
        "C:\\Windows\\Temp",
        "C:\\programdata\\WinTools",
    };
    const char* wincatDefaultName = "wincat.exe";

    // Check if the file exists
    BOOL isFound = FALSE;
    int i;
    char* wincatDefaultPath = (char*)calloc(MAX_PATH, 1);
    if (wincatDefaultPath == NULL)
        return FALSE;
    
    *ppDefaultToolPath = (char*)calloc(MAX_PATH, 1);
    if (*ppDefaultToolPath == NULL)
        return FALSE;

    for (i = 0; i < sizeof(defaultToolPath) / sizeof(char*) && !isFound; i++) {
        char* wincatDefaultPathTemp = (char*)malloc(MAX_PATH);
        if (wincatDefaultPathTemp != NULL) {
            if (GetModuleFileNameA(NULL, wincatDefaultPathTemp, MAX_PATH) > 0) {
                sprintf_s(wincatDefaultPath, MAX_PATH, "%s\\%s", defaultToolPath[i], wincatDefaultName);
                if (strcmp(wincatDefaultPath, wincatDefaultPathTemp) == 0)
                    isFound = TRUE;
                printf("wincatDefaultPath: %s\n", wincatDefaultPath);
                printf("wincatDefaultPathTemp: %s\n", wincatDefaultPathTemp);
            }
            free(wincatDefaultPathTemp);
        }
    }
    printf("\n------------------\n");
    printf("isFound: %d\n", isFound);
    printf("------------------\n\n");
    BOOL isCopySuccessfully = FALSE;
    if (!isFound) {
        for (i = 0; i < sizeof(defaultToolPath) / sizeof(char*) && !isCopySuccessfully; i++) {
            if (CreateDirectoryA(defaultToolPath[i], NULL) != ERROR_PATH_NOT_FOUND) {
                sprintf_s(wincatDefaultPath, MAX_PATH, "%s\\%s", defaultToolPath[i], wincatDefaultName);
                isCopySuccessfully = CopyWinNC(wincatDefaultPath);
                printf("wincatDefaultPath: %s %i\n", wincatDefaultPath, i);
            }
        }
    } else
        isCopySuccessfully = TRUE;
    i--;    

    strcpy_s(*ppDefaultToolPath, MAX_PATH, defaultToolPath[i]);
    *ppWincatDefaultPath = wincatDefaultPath;
    return isCopySuccessfully;
}

int main(){
    char* defaultToolPath = NULL;
    char* wincatDefaultPath = NULL;

    // Try to copy the file to the default location
    if (GetEnvVarAndCopyWincat(&defaultToolPath, &wincatDefaultPath)) {
        printf("------------------\n\n");
        printf("defaultToolPath: %s\n", defaultToolPath);
        printf("wincatDefaultPath: %s\n", wincatDefaultPath);
    }
    free(defaultToolPath);
    free(wincatDefaultPath);
    system("pause");
    return 0;
}